/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2010 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Xinchen Hui    <laruence@php.net>                           |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "SAPI.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_taint.h"

ZEND_DECLARE_MODULE_GLOBALS(taint)

/* {{{ taint_functions[]
 */
zend_function_entry taint_functions[] = {
	PHP_FE(untaint, NULL)
	PHP_FE(is_tainted, NULL)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ taint_module_entry
 */
zend_module_entry taint_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"taint",
	taint_functions,
	PHP_MINIT(taint),
	PHP_MSHUTDOWN(taint),
	PHP_RINIT(taint),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(taint),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(taint),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_TAINT_VERSION, /* Replace with version number for your extension */
#endif
	PHP_MODULE_GLOBALS(taint),
	NULL,
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

static void php_taint_mark_strings(zval *symbol_table TSRMLS_DC) /* {{{ */ {
	zval **ppzval;
	HashTable *ht = Z_ARRVAL_P(symbol_table);

	for(zend_hash_internal_pointer_reset(ht);
			zend_hash_has_more_elements(ht) == SUCCESS;
			zend_hash_move_forward(ht)) {
		if (zend_hash_get_current_data(ht, (void**)&ppzval) == FAILURE) {
			continue;
		}
        if (Z_TYPE_PP(ppzval) == IS_ARRAY) {
			php_taint_mark_strings(*ppzval TSRMLS_CC);
		} else if (IS_STRING == Z_TYPE_PP(ppzval)) {
			Z_STRVAL_PP(ppzval) = erealloc(Z_STRVAL_PP(ppzval), Z_STRLEN_PP(ppzval) + 1 + PHP_TAINT_MAGIC_LENGTH);
		    PHP_TAINT_MARK(*ppzval, PHP_TAINT_MAGIC_POSSIBLE); 
		}
	}
} /* }}} */

static inline void taint_pzval_unlock_func(zval *z, zend_free_op *should_free, int unref) /* {{{ */ {   
    if (!Z_DELREF_P(z)) {
        Z_SET_REFCOUNT_P(z, 1);
        Z_UNSET_ISREF_P(z);
        should_free->var = z;
    } else {
        should_free->var = 0;
        if (unref && Z_ISREF_P(z) && Z_REFCOUNT_P(z) == 1) {
			Z_UNSET_ISREF_P(z);
        }
    }
} /* }}} */
     
static inline void taint_pzval_unlock_free_func(zval *z) /* {{{ */ {
    if (!Z_DELREF_P(z)) {
        zval_dtor(z);
        safe_free_zval_ptr(z);
    }
} /* }}} */

static void php_taint_get_cv_address(zend_compiled_variable *cv, zval ***ptr, temp_variable *Ts TSRMLS_DC) /* {{{ */ {
	zval *new_zval = &EG(uninitialized_zval);

	Z_ADDREF_P(new_zval);
	zend_hash_quick_update(EG(active_symbol_table), cv->name, cv->name_len+1, cv->hash_value, &new_zval, sizeof(zval *), (void **)ptr);
}
/* }}} */

static zval * php_taint_get_zval_ptr_var(znode *node, temp_variable *Ts, zend_free_op *should_free TSRMLS_DC) /* {{{ */ {
    zval *ptr = TAINT_TS(node->u.var).var.ptr;
    if (ptr) {
        TAINT_PZVAL_UNLOCK(ptr, should_free);
        return ptr;
    } else {
        temp_variable *T = (temp_variable *)((char *)Ts + node->u.var);
        zval *str = T->str_offset.str;

        /* string offset */
        ALLOC_ZVAL(ptr);
        T->str_offset.ptr = ptr;
        should_free->var = ptr;

        if (T->str_offset.str->type != IS_STRING
            || ((int)T->str_offset.offset < 0)
            || (T->str_offset.str->value.str.len <= (int)T->str_offset.offset)) {
            ptr->value.str.val = STR_EMPTY_ALLOC();
            ptr->value.str.len = 0;
        } else {
            char c = str->value.str.val[T->str_offset.offset];

            ptr->value.str.val = estrndup(&c, 1);
            ptr->value.str.len = 1;
        }
        TAINT_PZVAL_UNLOCK_FREE(str);
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3) 
        ptr->refcount = 1;
        ptr->is_ref = 1;
#else
        ptr->refcount__gc = 1;
        ptr->is_ref__gc = 1;
#endif
        ptr->type = IS_STRING;
        return ptr;
    }
} /* }}} */

static zval * php_taint_get_zval_ptr_cv(znode *node, temp_variable *Ts TSRMLS_DC) /* {{{ */ {
	zval ***ptr = &TAINT_CV_OF(node->u.var);
	if (!*ptr) {
		zend_compiled_variable *cv = &TAINT_CV_DEF_OF(node->u.var);
		if (!EG(active_symbol_table) || zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE) {
			zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
			return &EG(uninitialized_zval);
		}
	}
	return **ptr;
} /* }}} */

static zval * php_taint_get_zval_ptr_tmp(znode *node, temp_variable *Ts, zend_free_op *should_free TSRMLS_DC) /* {{{ */ {   
    return should_free->var = &TAINT_TS(node->u.var).tmp_var;
} /* }}} */

static zval **php_taint_get_zval_ptr_ptr_var(znode *node, temp_variable *Ts, zend_free_op *should_free TSRMLS_DC) /* {{{ */ {
	zval** ptr_ptr = TAINT_TS(node->u.var).var.ptr_ptr;

	if (ptr_ptr) {
		TAINT_PZVAL_UNLOCK(*ptr_ptr, should_free);
	} else {
		/* string offset */
		TAINT_PZVAL_UNLOCK(TAINT_TS(node->u.var).str_offset.str, should_free);
	}
	return ptr_ptr;
} /* }}} */

static inline zval **php_taint_get_zval_ptr_ptr_cv(znode *node, temp_variable *Ts, int type TSRMLS_DC) /* {{{ */ {
	zval ***ptr = &TAINT_CV_OF(node->u.var);

	if (!*ptr) {
		zend_compiled_variable *cv = &TAINT_CV_DEF_OF(node->u.var);
		if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len+1, cv->hash_value, (void **) ptr )==FAILURE) {
			switch (type) {
				case BP_VAR_R:
				case BP_VAR_UNSET:
					zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
					/* break missing intentionally */
				case BP_VAR_IS:
					return &EG(uninitialized_zval_ptr);
					break;
				case BP_VAR_RW:
					zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
					/* break missing intentionally */
				case BP_VAR_W:
					php_taint_get_cv_address(cv, ptr, Ts TSRMLS_CC);
					break;
			}
		}
	}
	return *ptr;
} /* }}} */

static zval **php_taint_get_zval_ptr_ptr(znode *node, temp_variable *Ts, zend_free_op *should_free, int type TSRMLS_DC) /* {{{ */ {
	if (node->op_type == IS_CV) {
		should_free->var = 0;
		return php_taint_get_zval_ptr_ptr_cv(node, Ts, type TSRMLS_CC);
	} else if (node->op_type == IS_VAR) {
		return php_taint_get_zval_ptr_ptr_var(node, Ts, should_free TSRMLS_CC);
	} else {
		should_free->var = 0;
		return NULL;
	}
} /* }}} */

static void php_taint_error(const char *docref TSRMLS_DC, const char *format, ...) /* {{{ */ {
	va_list args;
	va_start(args, format);
	php_verror(docref, "", TAINT_G(error_level), format, args TSRMLS_CC);
	va_end(args);
} /* }}} */

static int php_taint_echo_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL;
	zend_free_op free_op1;


	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = TAINT_T(opline->op1.u.var).var.ptr;
			break;
		case IS_CV: {
				zval **t = TAINT_CV_OF(opline->op1.u.var);
				if (t && *t) {
					op1 = *t;
				}
		    } 
			break;
	}

	if (op1 && IS_STRING == Z_TYPE_P(op1) && PHP_TAINT_POSSIBLE(op1)) {
		php_taint_error("function.echo" TSRMLS_CC, "Argument contains data that is not converted with htmlspecialchars() or htmlentities()");
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_include_or_eval_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;

	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op1 = &opline->op1.u.constant;;
			break;
	}

	if ((op1 && IS_STRING == Z_TYPE_P(op1) && PHP_TAINT_POSSIBLE(op1)))
		switch (Z_LVAL(opline->op2.u.constant)) {
		case ZEND_INCLUDE_ONCE:
			php_taint_error("function.include_once" TSRMLS_CC, "File path contains data that might be tainted");
			break;
		case ZEND_REQUIRE_ONCE: 
			php_taint_error("function.require_once" TSRMLS_CC, "File path contains data that might be tainted");
			break;
		case ZEND_INCLUDE:
			php_taint_error("function.include" TSRMLS_CC, "File path contains data that might be tainted");
			break;
		case ZEND_REQUIRE: 
			php_taint_error("function.require" TSRMLS_CC, "File path contains data that might be tainted");
			break;
		case ZEND_EVAL:
			php_taint_error("function.eval" TSRMLS_CC, "eval code contains data that might be tainted");
			break;
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_concat_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;

	result = &TAINT_T(opline->result.u.var).tmp_var;
	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op1 = &opline->op1.u.constant;;
			break;
	}

	switch(opline->op2.op_type) {
		case IS_TMP_VAR:
			op2 = php_taint_get_zval_ptr_tmp(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_VAR:
			op2 = php_taint_get_zval_ptr_var(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_CV:
			op2 = php_taint_get_zval_ptr_cv(&opline->op2, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op2 = &opline->op2.u.constant;;
			break;
	}

	if ((op1 && IS_STRING == Z_TYPE_P(op1) && PHP_TAINT_POSSIBLE(op1)) 
			|| (op2 && IS_STRING == Z_TYPE_P(op2) && PHP_TAINT_POSSIBLE(op2))) {
		tainted = 1;
	}

	concat_function(result, op1, op2 TSRMLS_CC);

	if (tainted && IS_STRING == Z_TYPE_P(result)) {
		Z_STRVAL_P(result) = erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(result, PHP_TAINT_MAGIC_POSSIBLE);
	}

	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			zval_dtor(free_op1.var);
			break;
		case IS_VAR:
			if (free_op1.var) {
				zval_ptr_dtor(&free_op1.var);
			}
			break;
	}

	switch(opline->op2.op_type) {
		case IS_TMP_VAR:
			zval_dtor(free_op2.var);
			break;
		case IS_VAR:
			if (free_op2.var) {
				zval_ptr_dtor(&free_op2.var);
			}
			break;
	}

	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static int php_taint_assign_concat_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op2 = NULL, **var_ptr = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;
	zend_bool increment_opline = 0;

	if (opline->opcode != ZEND_ASSIGN_CONCAT) {
		return ZEND_USER_OPCODE_DISPATCH;
	}

	switch (opline->extended_value) {
		case ZEND_ASSIGN_OBJ:
		case ZEND_ASSIGN_DIM:
		    /* @FIXME */
			return ZEND_USER_OPCODE_DISPATCH;
			break;
		default:
			/* do nothing */
			break;
	}

	var_ptr = php_taint_get_zval_ptr_ptr(&opline->op1, execute_data->Ts, &free_op1, BP_VAR_RW TSRMLS_CC);

	if (!var_ptr) {
		zend_error_noreturn(E_ERROR, "Cannot use assign-op operators with overloaded objects nor string offsets");
	}

	switch(opline->op2.op_type) {
		case IS_TMP_VAR:
			op2 = php_taint_get_zval_ptr_tmp(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_VAR:
			op2 = php_taint_get_zval_ptr_var(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_CV:
			op2 = php_taint_get_zval_ptr_cv(&opline->op2, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op2 = &opline->op2.u.constant;;
			break;
	}

	SEPARATE_ZVAL_IF_NOT_REF(var_ptr);

	if ((*var_ptr && IS_STRING == Z_TYPE_PP(var_ptr) && PHP_TAINT_POSSIBLE(*var_ptr)) 
			|| (op2 && IS_STRING == Z_TYPE_P(op2) && PHP_TAINT_POSSIBLE(op2))) {
		tainted = 1;
	}

	concat_function(*var_ptr, *var_ptr, op2 TSRMLS_CC);

	if (tainted && IS_STRING == Z_TYPE_PP(var_ptr)) {
		Z_STRVAL_PP(var_ptr) = erealloc(Z_STRVAL_PP(var_ptr), Z_STRLEN_PP(var_ptr) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(*var_ptr, PHP_TAINT_MAGIC_POSSIBLE);
	}

	if (!((&opline->result)->u.EA.type & EXT_TYPE_UNUSED)) {
		TAINT_T(opline->result.u.var).var.ptr_ptr = var_ptr;
		TAINT_PZVAL_LOCK(*var_ptr);
		TAINT_AI_USE_PTR(TAINT_T(opline->result.u.var).var);
	}

	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			zval_dtor(free_op1.var);
			break;
		case IS_VAR:
			if (free_op1.var) {
				zval_ptr_dtor(&free_op1.var);
			}
			break;
	}

	switch(opline->op2.op_type) {
		case IS_VAR:
			if (free_op2.var) {
				zval_ptr_dtor(&free_op2.var);
			}
			break;
	}

	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static int php_taint_add_string_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;

	result = &TAINT_T(opline->result.u.var).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
	op1 = result;
	if (opline->op1.op_type == IS_UNUSED) {
		/* Initialize for erealloc in add_string_to_string */
		Z_STRVAL_P(op1) = NULL;
		Z_STRLEN_P(op1) = 0;
		Z_TYPE_P(op1) = IS_STRING;
		INIT_PZVAL(op1);
	}
#else
	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op1 = &opline->op1.u.constant;;
			break;
	}
#endif

	if ((op1 && IS_STRING == Z_TYPE_P(op1) && 
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
		Z_STRVAL_P(op1) &&
#endif	
		PHP_TAINT_POSSIBLE(op1))) {
		tainted = 1;
	}

	add_string_to_string(result, op1, &opline->op2.u.constant);

	if (tainted && IS_STRING == Z_TYPE_P(result)) {
		Z_STRVAL_P(result) = erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(result, PHP_TAINT_MAGIC_POSSIBLE);
	}

	/* FREE_OP is missing intentionally here - we're always working on the same temporary variable */
	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static int php_taint_add_char_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;

	result = &TAINT_T(opline->result.u.var).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
	op1 = result;
	if (opline->op1.op_type == IS_UNUSED) {
		/* Initialize for erealloc in add_string_to_string */
		Z_STRVAL_P(op1) = NULL;
		Z_STRLEN_P(op1) = 0;
		Z_TYPE_P(op1) = IS_STRING;
		INIT_PZVAL(op1);
	}
#else
	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op1 = &opline->op1.u.constant;;
			break;
	}
#endif

	if ((op1 && IS_STRING == Z_TYPE_P(op1) 
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
				&& Z_STRVAL_P(op1)
#endif
				&& PHP_TAINT_POSSIBLE(op1))) { 
		tainted = 1;
	}

	add_char_to_string(result, op1, &opline->op2.u.constant);

	if (tainted && IS_STRING == Z_TYPE_P(result)) {
		Z_STRVAL_P(result) = erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(result, PHP_TAINT_MAGIC_POSSIBLE);
	}

	/* FREE_OP is missing intentionally here - we're always working on the same temporary variable */
	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static int php_taint_add_var_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	zend_free_op free_op1, free_op2;
	uint tainted = 0;
	zval var_copy;
	int use_copy = 0;

	result = &TAINT_T(opline->result.u.var).tmp_var;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
	op1 = result;
	if (opline->op1.op_type == IS_UNUSED) {
		/* Initialize for erealloc in add_string_to_string */
		Z_STRVAL_P(op1) = NULL;
		Z_STRLEN_P(op1) = 0;
		Z_TYPE_P(op1) = IS_STRING;
		INIT_PZVAL(op1);
	}
#else
	switch(opline->op1.op_type) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_tmp(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op1 = &opline->op1.u.constant;;
			break;
	}
#endif

	switch(opline->op2.op_type) {
		case IS_TMP_VAR:
			op2 = php_taint_get_zval_ptr_tmp(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_VAR:
			op2 = php_taint_get_zval_ptr_var(&opline->op2, execute_data->Ts, &free_op2 TSRMLS_CC);
			break;
		case IS_CV:
			op2 = php_taint_get_zval_ptr_cv(&opline->op2, execute_data->Ts TSRMLS_CC);
			break;
		case IS_CONST:
	 		op2 = &opline->op2.u.constant;;
			break;
	}

	if ((op1 && IS_STRING == Z_TYPE_P(op1) 
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
				&& Z_STRVAL_P(op1) 
#endif
				&& PHP_TAINT_POSSIBLE(op1)) 
			|| (op2 && IS_STRING == Z_TYPE_P(op2) 
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2) 
				&& Z_STRVAL_P(op2) 
#endif
				&& PHP_TAINT_POSSIBLE(op2))) {
		tainted = 1;
	}

	if (Z_TYPE_P(op2) != IS_STRING) {
		zend_make_printable_zval(op2, &var_copy, &use_copy);
		if (use_copy) {
			op2 = &var_copy;
		}
	}

	add_string_to_string(result, op1, op2);

	if (use_copy) {
		zval_dtor(op2);
	}

	if (tainted && IS_STRING == Z_TYPE_P(result)) {
		Z_STRVAL_P(result) = erealloc(Z_STRVAL_P(result), Z_STRLEN_P(result) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(result, PHP_TAINT_MAGIC_POSSIBLE);
	}

	/* original comment, possibly problematic:
	 * FREE_OP is missing intentionally here - we're always working on the same temporary variable
	 * (Zeev):  I don't think it's problematic, we only use variables
	 * which aren't affected by FREE_OP(Ts, )'s anyway, unless they're
	 * string offsets or overloaded objects
	 */
	switch(opline->op2.op_type) {
		case IS_TMP_VAR:
			zval_dtor(free_op2.var);
			break;
		case IS_VAR:
			if (free_op2.var) {
				zval_ptr_dtor(&free_op2.var);
			}
			break;
	}

	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static void php_taint_fcall_check(ZEND_OPCODE_HANDLER_ARGS, zend_op *opline, char *fname, int len) /* {{{ */ {
	if (fname) {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3) 
		void **p = EG(argument_stack).top_element;
#else
	    void **p = EG(argument_stack)->top - 1;
#endif
		int arg_count = opline->extended_value;
		do { 
			if (strncmp("print_r", fname, len) == 0
				   || strncmp("passthru", fname, len) == 0
				   || strncmp("system", fname, len) == 0
				   || strncmp("exec", fname, len) == 0
				   || strncmp("mysqli_query", fname, len) == 0
				   || strncmp("mysql_query", fname, len) == 0 ) {
				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						php_taint_error(NULL TSRMLS_CC, "First argument contains data that might be tainted");
					}
				}
				break;
			}

			if (strncmp("escapeshellcmd", fname, len) == 0
					|| strncmp("htmlspecialchars", fname, len) == 0
					|| strncmp("escapeshellcmd", fname, len) == 0 
					|| strncmp("addcslashes", fname, len) == 0
					|| strncmp("addslashes", fname, len) == 0 
					|| strncmp("mysqli_escape_string", fname, len) == 0 
					|| strncmp("mysql_real_escape_string", fname, len) == 0 
					|| strncmp("mysql_escape_string", fname, len) == 0) {
				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						PHP_TAINT_MARK(el, PHP_TAINT_MAGIC_NONE);
					}
				}
				break;
			}
		} while (0);
	}

} /* }}} */

static int php_taint_do_fcall_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	zval *fname = &opline->op1.u.constant;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3) 
	zend_function *old_func = EG(function_state_ptr)->function;
	if (zend_hash_find(EG(function_table), fname->value.str.val, fname->value.str.len+1, (void **)&EG(function_state_ptr)->function) == SUCCESS) {
		php_taint_fcall_check(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU, opline, Z_STRVAL_P(fname), Z_STRLEN_P(fname));
	}
	EG(function_state_ptr)->function = old_func;
#else
	zend_function *old_func = EG(current_execute_data)->function_state.function;
	if (zend_hash_find(EG(function_table), fname->value.str.val, fname->value.str.len+1, (void **)&EG(current_execute_data)->function_state.function) == SUCCESS) {
		php_taint_fcall_check(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU, opline, Z_STRVAL_P(fname), Z_STRLEN_P(fname));
	}
	EG(current_execute_data)->function_state.function = old_func;
#endif
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_do_fcall_by_name_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	char *fname = execute_data->fbc->common.function_name;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3) 
	zend_function *old_func = EG(function_state_ptr)->function;
	EG(function_state_ptr)->function = execute_data->fbc;
	php_taint_fcall_check(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU, opline, fname, strlen(fname));
	EG(function_state_ptr)->function = old_func;
#else
	zend_function *old_func = EG(current_execute_data)->function_state.function;
	EG(current_execute_data)->function_state.function = execute_data->fbc;
	php_taint_fcall_check(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU, opline, fname, strlen(fname));
	EG(current_execute_data)->function_state.function = old_func;
#endif
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

#ifdef COMPILE_DL_TAINT
ZEND_GET_MODULE(taint)
#endif

static PHP_INI_MH(OnUpdateErrorLevel) /* {{{ */ {
	if (!new_value) {
		TAINT_G(error_level) = E_WARNING;
	} else {
		TAINT_G(error_level) = atoi(new_value);
	}
	return SUCCESS;
} /* }}} */

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("taint.enable", "0", PHP_INI_SYSTEM, OnUpdateBool, enable, zend_taint_globals, taint_globals)
	STD_PHP_INI_ENTRY("taint.error_level", "2", PHP_INI_ALL, OnUpdateErrorLevel, error_level, zend_taint_globals, taint_globals)
PHP_INI_END()
/* }}} */

/* {{{ proto bool untaint(string $str[, string ...]) 
 */
PHP_FUNCTION(untaint) 
{
	zval ***args;
	int argc;
	int i;

	if (!TAINT_G(enable)) {
		RETURN_TRUE;
	}

	argc = ZEND_NUM_ARGS();
	args = (zval ***)safe_emalloc(argc, sizeof(zval **), 0);

	if (ZEND_NUM_ARGS() == 0 || zend_get_parameters_array_ex(argc, args) == FAILURE) {
		efree(args);
		return;
	}

	for (i=0; i<argc; i++) {
		if (IS_STRING == Z_TYPE_PP(args[i]) && PHP_TAINT_POSSIBLE(*args[i])) {
			PHP_TAINT_MARK(*args[i], PHP_TAINT_MAGIC_UNTAINT);
		}
	}

	efree(args);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool is_tainted(string $str) 
 */
PHP_FUNCTION(is_tainted) 
{
	zval *arg;

	if (!TAINT_G(enable)) {
		RETURN_FALSE;
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE) {
		return;
	}

	if (IS_STRING == Z_TYPE_P(arg) && PHP_TAINT_POSSIBLE(arg)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(taint)
{
	REGISTER_INI_ENTRIES();
	zend_set_user_opcode_handler(ZEND_ECHO, php_taint_echo_handler);
	zend_set_user_opcode_handler(ZEND_INCLUDE_OR_EVAL, php_taint_include_or_eval_handler);
	zend_set_user_opcode_handler(ZEND_PRINT, php_taint_echo_handler);
	zend_set_user_opcode_handler(ZEND_CONCAT, php_taint_concat_handler);
	zend_set_user_opcode_handler(ZEND_ASSIGN_CONCAT, php_taint_assign_concat_handler);
	zend_set_user_opcode_handler(ZEND_ADD_CHAR, php_taint_add_char_handler);
	zend_set_user_opcode_handler(ZEND_ADD_STRING, php_taint_add_string_handler);
	zend_set_user_opcode_handler(ZEND_ADD_VAR, php_taint_add_var_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL, php_taint_do_fcall_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, php_taint_do_fcall_by_name_handler);
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(taint)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(taint)
{
	if (SG(sapi_started) || !TAINT_G(enable)) {
		return SUCCESS;
	}

    if (PG(http_globals)[TRACK_VARS_POST] && zend_hash_num_elements(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_POST]))) {
		php_taint_mark_strings(PG(http_globals)[TRACK_VARS_POST] TSRMLS_CC);
	}	

    if (PG(http_globals)[TRACK_VARS_GET] && zend_hash_num_elements(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]))) {
		php_taint_mark_strings(PG(http_globals)[TRACK_VARS_GET] TSRMLS_CC);
	}

    if (PG(http_globals)[TRACK_VARS_COOKIE] && zend_hash_num_elements(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_COOKIE]))) {
		php_taint_mark_strings(PG(http_globals)[TRACK_VARS_COOKIE] TSRMLS_CC);
	}

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(taint)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(taint)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "taint support", "enabled");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
