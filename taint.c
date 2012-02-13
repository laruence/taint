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
	PHP_FE(is_taint, NULL)
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
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
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
    if (!--z->refcount) {
        z->refcount = 1;
        z->is_ref = 0;
        should_free->var = z;
    } else {
        should_free->var = 0;
        if (unref && z->is_ref && z->refcount == 1) {
            z->is_ref = 0;
        }
    }
} /* }}} */
     
static inline void taint_pzval_unlock_free_func(zval *z) /* {{{ */ {
    if (!--z->refcount) {
        zval_dtor(z);
        safe_free_zval_ptr(z);
    }
} /* }}} */

static inline zval * php_taint_get_zval_ptr_var(znode *node, temp_variable *Ts, zend_free_op *should_free TSRMLS_DC) /* {{{ */ {
    zval *ptr = (*(temp_variable *)((char *)Ts + node->u.var)).var.ptr;
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
        ptr->refcount = 1;
        ptr->is_ref = 1;
        ptr->type = IS_STRING;
        return ptr;
    }
} /* }}} */

static zval * php_taint_get_zval_ptr_cv(znode *node, temp_variable *Ts TSRMLS_DC) /* {{{ */ {
	zval ***ptr = &TAINT_CV_OF(node->u.var);
	if (!*ptr) {
		zend_compiled_variable *cv = &TAINT_CV_DEF_OF(node->u.var);
		if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len + 1, cv->hash_value, (void **)ptr) == FAILURE) {
			zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
			return &EG(uninitialized_zval);
		}
	}
	return **ptr;
} /* }}} */

static zval * php_taint_get_zval_ptr_tmp(znode *node, temp_variable *Ts, zend_free_op *should_free TSRMLS_DC) /* {{{ */ {   
    return should_free->var = &(*(temp_variable *)((char *)Ts + node->u.var)).tmp_var;
} /* }}} */

static void php_taint_error(const char *docref, const char *format TSRMLS_CC, ...) /* {{{ */ {
	va_list args;
	va_start(args, format);
	php_verror(docref, "", E_WARNING, format, args TSRMLS_CC);
	va_end(args);
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
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts);
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
			op2 = php_taint_get_zval_ptr_cv(&opline->op2, execute_data->Ts);
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

static void php_taint_fcall_check(zend_op *opline, char *fname, int len TSRMLS_DC) /* {{{ */ {
	if (fname) {
		do { 
			if (strncmp("print_r", fname, len) == 0) {
				/* mixed print_r ( mixed $expression [, bool $return = false ] ) */
				void **p = EG(argument_stack).top_element;
				int arg_count = opline->extended_value;

				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						php_taint_error("function.print_r", "First argument contains data that might be tainted" TSRMLS_CC);
					}
				}
				break;
			}

			if (strncmp("exec", fname, len) == 0) {
				void **p = EG(argument_stack).top_element;
				int arg_count = opline->extended_value;

				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						php_taint_error("function.exec", "First argument contains data that might be tainted" TSRMLS_CC);
					}
				}
				break;
			}

			if (strncmp("system", fname, len) == 0) {
				void **p = EG(argument_stack).top_element;
				int arg_count = opline->extended_value;

				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						php_taint_error("function.system", "First argument contains data that might be tainted" TSRMLS_CC);
					}
				}
				break;
			}

			if (strncmp("passthru", fname, len) == 0) {
				void **p = EG(argument_stack).top_element;
				int arg_count = opline->extended_value;

				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
						php_taint_error("function.passthru", "First argument contains data that might be tainted" TSRMLS_CC);
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
				void **p = EG(argument_stack).top_element;
				int arg_count = opline->extended_value;

				if (arg_count) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (IS_STRING == Z_TYPE_P(el) && PHP_TAINT_POSSIBLE(el)) {
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
	zend_function *old_func = EG(function_state_ptr)->function;
	if (zend_hash_find(EG(function_table), fname->value.str.val, fname->value.str.len+1, (void **)&EG(function_state_ptr)->function) == SUCCESS) {
		php_taint_fcall_check(opline, Z_STRVAL_P(fname), Z_STRLEN_P(fname) TSRMLS_CC);
	}
	EG(function_state_ptr)->function = old_func;
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_do_fcall_by_name_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ {
    zend_op *opline = execute_data->opline;
	char *fname = execute_data->fbc->common.function_name;
	zend_function *old_func = EG(function_state_ptr)->function;
	EG(function_state_ptr)->function = execute_data->fbc;
	php_taint_fcall_check(opline, fname, strlen(fname) TSRMLS_CC);
	EG(function_state_ptr)->function = old_func;
	return ZEND_USER_OPCODE_DISPATCH;
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
			op1 = php_taint_get_zval_ptr_var(&opline->op1, execute_data->Ts, &free_op1 TSRMLS_CC);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(&opline->op1, execute_data->Ts);
			break;
	}

	if (op1 && IS_STRING == Z_TYPE_P(op1) && PHP_TAINT_POSSIBLE(op1)) {
		php_taint_error("function.echo", "Argument contains data that is not converted with htmlspecialchars() or htmlentities()" TSRMLS_CC);
	}

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
	STD_PHP_INI_ENTRY("taint.error_level", "E_WARNING", PHP_INI_ALL, OnUpdateErrorLevel, error_level, zend_taint_globals, taint_globals)
PHP_INI_END()
/* }}} */

/* {{{ php_taint_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_taint_init_globals(zend_taint_globals *taint_globals)
{
	taint_globals->global_value = 0;
	taint_globals->global_string = NULL;
}
*/
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

/* {{{ proto bool is_taint(string $str) 
 */
PHP_FUNCTION(is_taint) 
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

	if (TAINT_G(enable)) {
		zend_set_user_opcode_handler(ZEND_CONCAT, php_taint_concat_handler);
		zend_set_user_opcode_handler(ZEND_ECHO, php_taint_echo_handler);
		zend_set_user_opcode_handler(ZEND_PRINT, php_taint_echo_handler);
		zend_set_user_opcode_handler(ZEND_DO_FCALL, php_taint_do_fcall_handler);
		zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, php_taint_do_fcall_by_name_handler);
	}

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(taint)
{
	//UNREGISTER_INI_ENTRIES();
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
