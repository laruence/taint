/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2015 The PHP Group                                |
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

/* {{{ TAINT_ARG_INFO
*/
ZEND_BEGIN_ARG_INFO_EX(taint_arginfo, 0, 0, 1)
	ZEND_ARG_INFO(1, string)
	ZEND_ARG_INFO(1, ...)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(untaint_arginfo, 0, 0, 1)
	ZEND_ARG_INFO(1, string)
	ZEND_ARG_INFO(1, ...)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(is_tainted_arginfo, 0, 0, 1)
	ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()
	/* }}} */

/* {{{ taint_functions[]
*/
zend_function_entry taint_functions[] = {
	PHP_FE(taint, taint_arginfo)
	PHP_FE(untaint, untaint_arginfo)
	PHP_FE(is_tainted, is_tainted_arginfo)
	{NULL, NULL, NULL}
};
/* }}} */

/** {{{ module depends
*/
zend_module_dep taint_deps[] = {
	ZEND_MOD_CONFLICTS("xdebug")
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ taint_module_entry
*/
zend_module_entry taint_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	taint_deps,
	"taint",
	taint_functions,
	PHP_MINIT(taint),
	PHP_MSHUTDOWN(taint),
	PHP_RINIT(taint),
	PHP_RSHUTDOWN(taint),
	PHP_MINFO(taint),
	PHP_TAINT_VERSION,
	PHP_MODULE_GLOBALS(taint),
	NULL,
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

static struct taint_overridden_fucs /* {{{ */ {
	php_func strval;
	php_func sprintf;
	php_func vsprintf;
	php_func explode;
	php_func implode;
	php_func trim;
	php_func rtrim;
	php_func ltrim;
	php_func strstr;
	php_func str_pad;
	php_func str_replace;
	php_func substr;
	php_func strtolower;
	php_func strtoupper;
} taint_origin_funcs;

#define TAINT_O_FUNC(m) (taint_origin_funcs.m)
/* }}} */

static void php_taint_mark_strings(zend_array *symbol_table) /* {{{ */ {
	zval *val;
	ZEND_HASH_FOREACH_VAL(symbol_table, val) {
		if (Z_TYPE_P(val) == IS_ARRAY) {
			php_taint_mark_strings(Z_ARRVAL_P(val));
		} else if (IS_STRING == Z_TYPE_P(val) && Z_STRLEN_P(val)) {
			TAINT_MARK(Z_STR_P(val));
		}
	} ZEND_HASH_FOREACH_END();
} /* }}} */

static zval *php_taint_get_zval_ptr_var(zend_execute_data *execute_data, uint32_t var, zend_free_op *should_free) /* {{{ */
{
	zval *ret = EX_VAR(var);

	*should_free = ret;
	return ret;
}
/* }}} */

static zval *php_taint_get_zval_ptr_cv(zend_execute_data *execute_data, uint32_t var, int type) /* {{{ */
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		return NULL;
	}
	return ret;
}
/* }}} */

static zval *php_taint_get_zval_ptr_const(zend_execute_data *execute_data, znode_op op) /* {{{ */
{
	return EX_CONSTANT(op);
}
/* }}} */

static void php_taint_error(const char *docref, const char *format, ...) /* {{{ */ {
	va_list args;
	va_start(args, format);
	php_verror(docref, "", TAINT_G(error_level), format, args);
	va_end(args);
} /* }}} */

static int php_taint_echo_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op1;
	zval *op1 = NULL;

	switch (TAINT_OP1_TYPE(opline)) {
		case IS_TMP_VAR:
			op1 = php_taint_get_zval_ptr_var(execute_data, opline->op1.var, &free_op1);
			break;
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(execute_data, opline->op1.var, &free_op1);
			ZVAL_DEREF(op1);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(execute_data, opline->op1.var, BP_VAR_R);
			ZVAL_DEREF(op1);
			break;
		default:
			break;
	}

	if (op1 && IS_STRING == Z_TYPE_P(op1) && TAINT_POSSIBLE(Z_STR_P(op1))) {
		if (ZEND_ECHO == opline->opcode) {
			php_taint_error("statement.echo", "Attempt to echo a string that might be tainted");
		} else {
			php_taint_error("statement.print", "Attempt to print a string that might be tainted");
		}
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_include_or_eval_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op1;
	zval *op1 = NULL;

	switch (TAINT_OP1_TYPE(opline)) {
		case IS_TMP_VAR:
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(execute_data, opline->op1.var, &free_op1);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(execute_data, opline->op1.var, BP_VAR_R);
			break;
		default:
			break;
	}

	if ((op1 && IS_STRING == Z_TYPE_P(op1) && TAINT_POSSIBLE(Z_STR_P(op1))))
		switch (opline->extended_value) {
			case ZEND_INCLUDE_ONCE:
				php_taint_error("statement.include_once", "File path contains data that might be tainted");
				break;
			case ZEND_REQUIRE_ONCE:
				php_taint_error("statement.require_once", "File path contains data that might be tainted");
				break;
			case ZEND_INCLUDE:
				php_taint_error("statement.include", "File path contains data that might be tainted");
				break;
			case ZEND_REQUIRE:
				php_taint_error("statement.require", "File path contains data that might be tainted");
				break;
			case ZEND_EVAL:
				php_taint_error("statement.eval", "Eval code contains data that might be tainted");
				break;
		}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

#if 0
static int php_taint_concat_handler(zend_execute_data *execute_data) /* {{{ */ {
	zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	taint_free_op free_op1, free_op2;
	int tainted = 0;

	result = EX_VAR(opline->result.var);
	switch (TAINT_OP1_TYPE(opline)) {
		case IS_TMP_VAR:
		case IS_VAR:
			op1 = php_taint_get_zval_ptr_var(execute_data, opline->op1.var, &free_op1);
			break;
		case IS_CV:
			op1 = php_taint_get_zval_ptr_cv(execute_data, opline->op1.var, BP_VAR_R);
			break;
		case IS_CONST:
			op1 = php_taint_get_zval_ptr_const(opline->op1);
			break;
	}

	switch (TAINT_OP2_TYPE(opline)) {
		case IS_TMP_VAR:
		case IS_VAR:
			op2 = php_taint_get_zval_ptr_var(execute_data, opline->op2.var, &free_op2);
			break;
		case IS_CV:
			op2 = php_taint_get_zval_ptr_cv(execute_data, opline->op2.var, BP_VAR_R);
			break;
		case IS_CONST:
			op2 = php_taint_get_zval_ptr_const(opline->op2);
			break;
	}

	if ((op1 && IS_STRING == Z_TYPE_P(op1) && TAINT_POSSIBLE(Z_STR_P(op1)))
			|| (op2 && IS_STRING == Z_TYPE_P(op2) && TAINT_POSSIBLE(Z_STR_P(op2)))) {
		tainted = 1;
	}

	concat_function(result, op1, op2);

	if (tainted && IS_STRING == Z_TYPE_P(result)) {
		TAINT_MARK(result);
	}

	if (TAINT_OP1_TYPE(opline) & (IS_VAR|IS_TMP_VAR)) {
		zval_ptr_dtor_nogc(&free_op1);
	}

	if (TAINT_OP2_TYPE(opline) & (IS_VAR|IS_TMP_VAR)) {
		zval_ptr_dtor_nogc(&free_op2);
	}

	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

static zval **php_taint_fetch_dimension_address_inner(HashTable *ht, zval *dim, int dim_type, int type) /* {{{ */ {
	zval **retval;
	char *offset_key;
	int offset_key_length;
	ulong hval;

	switch (dim->type) {
		case IS_NULL:
			offset_key = "";
			offset_key_length = 0;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 3)
			hval = zend_inline_hash_func("", 1);
#endif
			goto fetch_string_dim;

		case IS_STRING:
			offset_key = dim->value.str.val;
			offset_key_length = dim->value.str.len;
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 3)
			if (dim_type == IS_CONST) {
				hval = Z_HASH_P(dim);
			} else {
				ZEND_HANDLE_NUMERIC_EX(offset_key, offset_key_length+1, hval, goto num_index);
				if (IS_INTERNED(offset_key)) {
					hval = INTERNED_HASH(offset_key);
				} else {
					hval = zend_hash_func(offset_key, offset_key_length+1);
				}
			}
#endif

fetch_string_dim:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
			if (zend_symtable_find(ht, offset_key, offset_key_length+1, (void **) &retval) == FAILURE) {
#else
				if (zend_hash_quick_find(ht, offset_key, offset_key_length+1, hval, (void **) &retval) == FAILURE) {
#endif
					switch (type) {
						case BP_VAR_R:
							zend_error(E_NOTICE, "Undefined index: %s", offset_key);
							/* break missing intentionally */
						case BP_VAR_UNSET:
						case BP_VAR_IS:
							retval = &EG(uninitialized_zval_ptr);
							break;
						case BP_VAR_RW:
							zend_error(E_NOTICE,"Undefined index: %s", offset_key);
							/* break missing intentionally */
						case BP_VAR_W: {
										   zval *new_zval = &EG(uninitialized_zval);
										   Z_ADDREF_P(new_zval);
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
										   zend_symtable_update(ht, offset_key, offset_key_length+1, &new_zval, sizeof(zval *), (void **) &retval);
#else
										   zend_hash_quick_update(ht, offset_key, offset_key_length+1, hval, &new_zval, sizeof(zval *), (void **) &retval);
#endif
									   }
									   break;
					}
				}
#if 0
			}
#endif
			break;
		case IS_DOUBLE:
			hval = zend_dval_to_lval(Z_DVAL_P(dim));
			goto num_index;
		case IS_RESOURCE:
			zend_error(E_STRICT, "Resource ID#%ld used as offset, casting to integer (%ld)", Z_LVAL_P(dim), Z_LVAL_P(dim));
			/* Fall Through */
		case IS_BOOL:
		case IS_LONG:
			hval = Z_LVAL_P(dim);
num_index:
			if (zend_hash_index_find(ht, hval, (void **) &retval) == FAILURE) {
				switch (type) {
					case BP_VAR_R:
						zend_error(E_NOTICE,"Undefined offset: %ld", hval);
						/* break missing intentionally */
					case BP_VAR_UNSET:
					case BP_VAR_IS:
						retval = &EG(uninitialized_zval_ptr);
						break;
					case BP_VAR_RW:
						zend_error(E_NOTICE,"Undefined offset: %ld", hval);
						/* break missing intentionally */
					case BP_VAR_W: {
									   zval *new_zval = &EG(uninitialized_zval);

									   Z_ADDREF_P(new_zval);
									   zend_hash_index_update(ht, hval, &new_zval, sizeof(zval *), (void **) &retval);
								   }
								   break;
				}
			}
			break;

		default:
			zend_error(E_WARNING, "Illegal offset type");
			return (type == BP_VAR_W || type == BP_VAR_RW) ?
				&EG(error_zval_ptr) : &EG(uninitialized_zval_ptr);
	}
	return retval;
} /* }}} */

static int php_taint_binary_assign_op_obj_helper(int (*binary_op)(zval *result, zval *op1, zval *op2), zend_execute_data *execute_data) /* {{{ */ {
	zend_op *opline = execute_data->opline;
	zend_op *op_data = opline+1;
	taint_free_op free_op1 = {0}, free_op2 = {0}, free_op_data1 = {0};
	zval **object_ptr = NULL, *object = NULL, *property = NULL;
	int have_get_ptr = 0;
	uint tainted = 0;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
	zval *value = php_taint_get_zval_ptr(&op_data->op1, execute_data->Ts, &free_op_data1, BP_VAR_R);
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
	zval *value = php_taint_get_zval_ptr((opline+1)->op1_type, &(opline+1)->op1, execute_data, &free_op_data1, BP_VAR_R);
#else
	zval *value = php_taint_get_zval_ptr((opline+1)->op1_type, &(opline+1)->op1, execute_data->Ts, &free_op_data1, BP_VAR_R);
#endif
	zval **retval = &TAINT_T(TAINT_RESULT_VAR(opline)).var.ptr;

	switch (TAINT_OP1_TYPE(opline)) {
		case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
			object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data, &free_op1);
#else
			object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1);
#endif
			if (!object_ptr) {
				zend_error(E_ERROR, "Cannot use string offset as an object");
				return 0;
			}
			break;
		case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
			object_ptr = php_taint_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_W);
#else
			object_ptr = php_taint_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W);
#endif
			break;
		case IS_UNUSED:
			object_ptr = php_taint_get_obj_zval_ptr_ptr_unused();
			break;
		default:
			/* do nothing */
			break;
	}

	switch(TAINT_OP2_TYPE(opline)) {
		case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
			property = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
			property = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
			break;
		case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
			property = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
			property = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
			break;
		case IS_CV:
			property = php_taint_get_zval_ptr_cv(TAINT_OP2_NODE_PTR(opline), TAINT_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R));
			break;
		case IS_CONST:
			property = TAINT_OP2_CONSTANT_PTR(opline);
			break;
		case IS_UNUSED:
			property = NULL;
			break;
		default:
			/* do nothing */
			break;
	}

	TAINT_T(TAINT_RESULT_VAR(opline)).var.ptr_ptr = NULL;
	make_real_object(object_ptr);
	object = *object_ptr;

	if (Z_TYPE_P(object) != IS_OBJECT) {
		zend_error(E_WARNING, "Attempt to assign property of non-object");
		switch(TAINT_OP2_TYPE(opline)) {
			case IS_TMP_VAR:
				zval_dtor(free_op2.var);
				break;
			case IS_VAR:
				if (free_op2.var) {zval_ptr_dtor(&free_op2.var);};
				break;
			case IS_CV:
			case IS_CONST:
			case IS_UNUSED:
			default:
				/* do nothing */
				break;
		}
		TAINT_FREE_OP(free_op_data1);

		if (TAINT_RETURN_VALUE_USED(opline)) {
			*retval = EG(uninitialized_zval_ptr);
			Z_ADDREF_P(*retval);
		}
	} else {
		/* here we are sure we are dealing with an object */
		if (IS_TMP_VAR == TAINT_OP2_TYPE(opline)) {
			MAKE_REAL_ZVAL_PTR(property);
		}

		/* here property is a string */
		if (opline->extended_value == ZEND_ASSIGN_OBJ
				&& Z_OBJ_HT_P(object)->get_property_ptr_ptr) {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
			zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property);
#elif (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
			zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property, BP_VAR_RW, ((TAINT_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL));
#else
			zval **zptr = Z_OBJ_HT_P(object)->get_property_ptr_ptr(object, property, ((IS_CONST == IS_CONST) ? opline->op2.literal : NULL));
#endif
			if (zptr != NULL) { 			/* NULL means no success in getting PTR */
				if ((*zptr && IS_STRING == Z_TYPE_PP(zptr) && Z_STRLEN_PP(zptr) && TAINT_POSSIBLE(*zptr)) 
						|| (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && TAINT_POSSIBLE(value))){
					tainted = 1;
				}

				SEPARATE_ZVAL_IF_NOT_REF(zptr);
				have_get_ptr = 1;

				binary_op(*zptr, *zptr, value);
				if (tainted && IS_STRING == Z_TYPE_PP(zptr) && Z_STRLEN_PP(zptr)) {
					Z_STRVAL_PP(zptr) = erealloc(Z_STRVAL_PP(zptr), Z_STRLEN_PP(zptr) + 1 + PHP_TAINT_MAGIC_LENGTH);
					TAINT_MARK(*zptr, PHP_TAINT_MAGIC_POSSIBLE);
				}
				if (TAINT_RETURN_VALUE_USED(opline)) {
					*retval = *zptr;
					Z_ADDREF_P(*retval);
				}
			}
		}

		if (!have_get_ptr) {
			zval *z = NULL;

			switch (opline->extended_value) {
				case ZEND_ASSIGN_OBJ:
					if (Z_OBJ_HT_P(object)->read_property) {
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
						z = Z_OBJ_HT_P(object)->read_property(object, property, BP_VAR_R);
#else
						z = Z_OBJ_HT_P(object)->read_property(object, property, BP_VAR_R, ((TAINT_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL));
#endif
					}
					break;
				case ZEND_ASSIGN_DIM:
					if (Z_OBJ_HT_P(object)->read_dimension) {
						z = Z_OBJ_HT_P(object)->read_dimension(object, property, BP_VAR_R);
					}
					break;
			}
			if (z) {
				if (Z_TYPE_P(z) == IS_OBJECT && Z_OBJ_HT_P(z)->get) {
					zval *value = Z_OBJ_HT_P(z)->get(z);

					if (Z_REFCOUNT_P(z) == 0) {
						zval_dtor(z);
						FREE_ZVAL(z);
					}
					z = value;
				}
				Z_ADDREF_P(z);
				if ((z && IS_STRING == Z_TYPE_P(z) && Z_STRLEN_P(z) && TAINT_POSSIBLE(z)) 
						|| (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && TAINT_POSSIBLE(value))) {
					tainted = 1;
				}

				SEPARATE_ZVAL_IF_NOT_REF(&z);
				binary_op(z, z, value);
				if (tainted && IS_STRING == Z_TYPE_P(z) && Z_STRLEN_P(z)) {
					Z_STRVAL_P(z) = erealloc(Z_STRVAL_P(z), Z_STRLEN_P(z) + 1 + PHP_TAINT_MAGIC_LENGTH);
					TAINT_MARK(z, PHP_TAINT_MAGIC_POSSIBLE);
				}

				switch (opline->extended_value) {
					case ZEND_ASSIGN_OBJ:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
						Z_OBJ_HT_P(object)->write_property(object, property, z);
#else
						Z_OBJ_HT_P(object)->write_property(object, property, z, ((TAINT_OP2_TYPE(opline) == IS_CONST) ? opline->op2.literal : NULL));
#endif
						break;
					case ZEND_ASSIGN_DIM:
						Z_OBJ_HT_P(object)->write_dimension(object, property, z);
						break;
				}
				if (TAINT_RETURN_VALUE_USED(opline)) {
					*retval = z;
					Z_ADDREF_P(*retval);
				}
				zval_ptr_dtor(&z);
			} else {
				zend_error(E_WARNING, "Attempt to assign property of non-object");
				if (TAINT_RETURN_VALUE_USED(opline)) {
					*retval = EG(uninitialized_zval_ptr);
					Z_ADDREF_P(*retval);
				}
			}
		}

		switch(TAINT_OP2_TYPE(opline)) {
			case IS_TMP_VAR:
				zval_ptr_dtor(&property);
				break;
			case IS_VAR:
				if (free_op2.var) {zval_ptr_dtor(&free_op2.var);};
				break;
			case IS_CV:
			case IS_CONST:
			case IS_UNUSED:
			default:
				/* do nothing */
				break;
		}

		TAINT_FREE_OP(free_op_data1);
	}

	if (IS_VAR == TAINT_OP1_TYPE(opline) && free_op1.var) {zval_ptr_dtor(&free_op1.var);};
	/* assign_obj has two opcodes! */
	execute_data->opline++;
	execute_data->opline++;
	return ZEND_USER_OPCODE_CONTINUE; 
} /* }}} */ 

static int php_taint_binary_assign_op_helper(int (*binary_op)(zval *result, zval *op1, zval *op2), zend_execute_data *execute_data) /* {{{ */ {
	zend_op *opline = execute_data->opline;
	taint_free_op free_op1 = {0}, free_op2 = {0}, free_op_data2 = {0}, free_op_data1 = {0};
	zval **var_ptr = NULL, **object_ptr = NULL, *value = NULL;
	zend_bool increment_opline = 0;
	uint tainted = 0;

	switch (opline->extended_value) {
		case ZEND_ASSIGN_OBJ:
			return php_taint_binary_assign_op_obj_helper(binary_op, zend_execute_data *execute_data);
			break;
		case ZEND_ASSIGN_DIM: {
								  switch (TAINT_OP1_TYPE(opline)) {
									  case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
										  object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data, &free_op1);
#else
										  object_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1);
#endif
										  if (object_ptr && !(free_op1.var != NULL)) {
											  Z_ADDREF_P(*object_ptr);  /* undo the effect of get_obj_zval_ptr_ptr() */
										  }
										  break;
									  case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
										  object_ptr = php_taint_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_W);
#else
										  object_ptr = php_taint_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_W);
#endif
										  break;
									  case IS_UNUSED:
										  object_ptr = php_taint_get_obj_zval_ptr_ptr_unused();
										  if (object_ptr) {
											  Z_ADDREF_P(*object_ptr);  /* undo the effect of get_obj_zval_ptr_ptr() */
										  }
										  break;
									  default:
										  /* do nothing */
										  break;
								  }

								  if (object_ptr && Z_TYPE_PP(object_ptr) == IS_OBJECT) {
									  return php_taint_binary_assign_op_obj_helper(binary_op, zend_execute_data *execute_data);
								  } else {
									  zend_op *op_data = opline+1;

									  zval *dim;

									  switch(TAINT_OP2_TYPE(opline)) {
										  case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
											  dim = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
											  dim = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
											  break;
										  case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
											  dim = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
											  dim = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
											  break;
										  case IS_CV:
											  dim = php_taint_get_zval_ptr_cv(TAINT_OP2_NODE_PTR(opline), TAINT_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R));
											  break;
										  case IS_CONST:
											  dim = TAINT_OP2_CONSTANT_PTR(opline);
											  break;
										  case IS_UNUSED:
											  dim = NULL;
											  break;
										  default:
											  /* do nothing */
											  break;
									  }

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
									  if (TAINT_OP2_TYPE(opline) == IS_TMP_VAR) {
										  php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, 1, BP_VAR_RW);
									  } else {
										  php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, 0, BP_VAR_RW);
									  }
									  value = php_taint_get_zval_ptr(&op_data->op1, execute_data->Ts, &free_op_data1, BP_VAR_R);
									  var_ptr = php_taint_get_zval_ptr_ptr(&op_data->op2, execute_data->Ts, &free_op_data2, BP_VAR_RW);
#else
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
									  php_taint_fetch_dimension_address(&TAINT_T((opline+1)->op2.var), object_ptr, dim, IS_TMP_VAR, BP_VAR_RW);
									  value = php_taint_get_zval_ptr((opline+1)->op1_type, &(opline+1)->op1, execute_data, &free_op_data1, BP_VAR_R);
									  var_ptr = php_taint_get_zval_ptr_ptr_var((opline+1)->op2.var, execute_data, &free_op_data2);
#else
									  php_taint_fetch_dimension_address(&TAINT_T(TAINT_OP2_VAR(op_data)), object_ptr, dim, TAINT_OP2_TYPE(opline), BP_VAR_RW);
									  value = php_taint_get_zval_ptr((opline+1)->op1_type, &(opline+1)->op1, execute_data->Ts, &free_op_data1, BP_VAR_R);
									  var_ptr = php_taint_get_zval_ptr_ptr_var((opline+1)->op2.var, execute_data->Ts, &free_op_data2);
#endif
#endif
									  increment_opline = 1;
								  }
							  }
							  break;
		default:
							  switch(TAINT_OP2_TYPE(opline)) {
								  case IS_TMP_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
									  value = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
									  value = php_taint_get_zval_ptr_tmp(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
									  break;
								  case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
									  value = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data, &free_op2);
#else
									  value = php_taint_get_zval_ptr_var(TAINT_OP2_NODE_PTR(opline), execute_data->Ts, &free_op2);
#endif
									  break;
								  case IS_CV:
									  value = php_taint_get_zval_ptr_cv(TAINT_OP2_NODE_PTR(opline), TAINT_GET_ZVAL_PTR_CV_2ND_ARG(BP_VAR_R));
									  break;
								  case IS_CONST:
									  value = TAINT_OP2_CONSTANT_PTR(opline);
									  break;
								  case IS_UNUSED:
									  value = NULL;
									  break;
								  default:
									  /* do nothing */
									  break;
							  }

							  switch (TAINT_OP1_TYPE(opline)) {
								  case IS_VAR:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION == 5)
									  var_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data, &free_op1);
#else
									  var_ptr = php_taint_get_zval_ptr_ptr_var(TAINT_OP1_NODE_PTR(opline), execute_data->Ts, &free_op1);
#endif
									  break;
								  case IS_CV:
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
									  var_ptr = php_taint_get_zval_ptr_ptr_cv(&opline->op1, execute_data->Ts, BP_VAR_RW);
#else
									  var_ptr = php_taint_get_zval_ptr_ptr_cv(opline->op1.var, BP_VAR_RW);
#endif
									  break;
								  case IS_UNUSED:
									  var_ptr = NULL;
									  break;
								  default:
									  /* do nothing */
									  break;
							  }
							  /* do nothing */
							  break;
	}

	if (!var_ptr) {
		zend_error(E_ERROR, "Cannot use assign-op operators with overloaded objects nor string offsets");
		return 0;
	}

	if (*var_ptr == EG(error_zval_ptr)) {
		if (TAINT_RETURN_VALUE_USED(opline)) {
			TAINT_T(TAINT_RESULT_VAR(opline)).var.ptr_ptr = &EG(uninitialized_zval_ptr);
			Z_ADDREF_P(*TAINT_T(TAINT_RESULT_VAR(opline)).var.ptr_ptr);
			TAINT_AI_USE_PTR(TAINT_T(TAINT_RESULT_VAR(opline)).var);
		}

		switch(TAINT_OP2_TYPE(opline)) {
			case IS_TMP_VAR:
				zval_dtor(free_op2.var);
				break;
			case IS_VAR:
				if (free_op2.var) {zval_ptr_dtor(&free_op2.var);};
				break;
			case IS_CV:
			case IS_CONST:
			case IS_UNUSED:
			default:
				/* do nothing */
				break;
		}

		if (IS_VAR == TAINT_OP1_TYPE(opline) && free_op1.var) {zval_ptr_dtor(&free_op1.var);};
		if (increment_opline) {
			execute_data->opline++;
		}
		execute_data->opline++;
	}

	if ((*var_ptr && IS_STRING == Z_TYPE_PP(var_ptr) && Z_STRLEN_PP(var_ptr) && TAINT_POSSIBLE(*var_ptr))
			|| (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && TAINT_POSSIBLE(value))) {
		tainted = 1;
	}

	SEPARATE_ZVAL_IF_NOT_REF(var_ptr);

	if(Z_TYPE_PP(var_ptr) == IS_OBJECT && Z_OBJ_HANDLER_PP(var_ptr, get)
			&& Z_OBJ_HANDLER_PP(var_ptr, set)) {
		/* proxy object */
		zval *objval = Z_OBJ_HANDLER_PP(var_ptr, get)(*var_ptr);
		Z_ADDREF_P(objval);
		if ((objval && IS_STRING == Z_TYPE_P(objval) && Z_STRLEN_P(objval) && TAINT_POSSIBLE(objval))
				|| (value && IS_STRING == Z_TYPE_P(value) && Z_STRLEN_P(value) && TAINT_POSSIBLE(value))) {
			tainted = 1;
		}
		binary_op(objval, objval, value);
		if (tainted && IS_STRING == Z_TYPE_P(objval) && Z_STRLEN_P(objval)) {
			Z_STRVAL_P(objval) = erealloc(Z_STRVAL_P(objval), Z_STRLEN_P(objval) + 1 + PHP_TAINT_MAGIC_LENGTH);
			TAINT_MARK(objval, PHP_TAINT_MAGIC_POSSIBLE);
		}

		Z_OBJ_HANDLER_PP(var_ptr, set)(var_ptr, objval);
		zval_ptr_dtor(&objval);
	} else {
		binary_op(*var_ptr, *var_ptr, value);
		if (tainted && IS_STRING == Z_TYPE_PP(var_ptr) && Z_STRLEN_PP(var_ptr)) {
			Z_STRVAL_PP(var_ptr) = erealloc(Z_STRVAL_PP(var_ptr), Z_STRLEN_PP(var_ptr) + 1 + PHP_TAINT_MAGIC_LENGTH);
			TAINT_MARK(*var_ptr, PHP_TAINT_MAGIC_POSSIBLE);
		}
	}

	if (TAINT_RETURN_VALUE_USED(opline)) {
		TAINT_T(TAINT_RESULT_VAR(opline)).var.ptr_ptr = var_ptr;
		Z_ADDREF_P(*var_ptr);
		TAINT_AI_USE_PTR(TAINT_T(TAINT_RESULT_VAR(opline)).var);
	}

	switch(TAINT_OP2_TYPE(opline)) {
		case IS_TMP_VAR:
			zval_dtor(free_op2.var);
			break;
		case IS_VAR:
			if (free_op2.var) {zval_ptr_dtor(&free_op2.var);};
			break;
		case IS_CV:
		case IS_CONST:
		case IS_UNUSED:
		default:
			/* do nothing */
			break;
	}

	if (increment_opline) {
		execute_data->opline++;
		TAINT_FREE_OP(free_op_data1);
		TAINT_FREE_OP_VAR_PTR(free_op_data2);
	}
	if (IS_VAR == TAINT_OP1_TYPE(opline) && free_op1.var) {zval_ptr_dtor(&free_op1.var);};

	execute_data->opline++;
	return ZEND_USER_OPCODE_CONTINUE; 
} /* }}} */

static int php_taint_assign_concat_handler(zend_execute_data *execute_data) /* {{{ */ {
	return php_taint_binary_assign_op_helper(concat_function, zend_execute_data *execute_data);
} /* }}} */

static int php_taint_rope_handler(zend_execute_data *execute_data) /* {{{ */ {
	zend_op *opline = execute_data->opline;
	zval *op1 = NULL, *op2 = NULL, *result;
	taint_free_op free_op2;
	int tainted = 0;

	rope = (zend_string *)EX_VAR(opline->op1.var);

	execute_data->opline++;

	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */
#endif

static void php_taint_fcall_check(zend_execute_data *ex, const zend_op *opline, zend_function *fbc) /* {{{ */ {
	int arg_count = ZEND_CALL_NUM_ARGS(ex);

	if (!arg_count) {
		return;
	}

	if (fbc->common.scope == NULL) {
		do {
			const char *fname = ZSTR_VAL(fbc->common.function_name);
			size_t len = ZSTR_LEN(fbc->common.function_name);
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (strncmp("print_r", fname, len) == 0
					|| strncmp("fopen", fname, len) == 0
					|| strncmp("opendir", fname, len) == 0
					|| strncmp("dirname", fname, len) == 0
					|| strncmp("basename", fname, len) == 0
					|| strncmp("pathinfo", fname, len) == 0
					|| strncmp("file", fname, len) == 0 ) {
				zval *p = ZEND_CALL_ARG(ex, 1);
				if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
					php_taint_error(NULL, "First argument contains data that might be tainted");
				}
				break;
			}

			if (strncmp("printf", fname, len) == 0) {
				if (arg_count > 1) {
					uint32_t i;
					for (i = 0; i < arg_count; i++) {
						zval *p = ZEND_CALL_ARG(ex, i + 1);
						if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
							php_taint_error(NULL, "%dth argument contains data that might be tainted", i + 1);
							break;
						}
					}
				}
				break;
			}

			if (strncmp("vprintf", fname, len) == 0) {
				if (arg_count > 1) {
					zend_string *key;
					zend_long idx;
					zval *val, *p = ZEND_CALL_ARG(ex, 1);
					if (IS_ARRAY != Z_TYPE_P(p) || zend_hash_num_elements(Z_ARRVAL_P(p))) {
						break;
					}

					ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(p), idx, key, val) {
						if (IS_STRING == Z_TYPE_P(val) && TAINT_POSSIBLE(Z_STR_P(val))) {
							if (key) {
								php_taint_error(NULL,
										"Second argument contains data(index:%s) that might be tainted", ZSTR_VAL(key));
							} else {
								php_taint_error(NULL,
										"Second argument contains data(index:%ld) that might be tainted", idx);
							}
							break;
						}
					} ZEND_HASH_FOREACH_END();
				}
				break;
			}

			if (strncmp("file_put_contents", fname, len) == 0
					|| strncmp("fwrite", fname, len) == 0) {
				if (arg_count > 1) {
					zval *fp, *str;

					fp = ZEND_CALL_ARG(ex, 1);
					str = ZEND_CALL_ARG(ex, 2);

					if (IS_RESOURCE == Z_TYPE_P(fp)) {
						break;
					} else if (IS_STRING == Z_TYPE_P(fp)) {
						if (strncasecmp("php://output", Z_STRVAL_P(fp), Z_STRLEN_P(fp))) {
							break;
						}
					}
					if (IS_STRING == Z_TYPE_P(str) && TAINT_POSSIBLE(Z_STR_P(str))) {
						php_taint_error(NULL, "Second argument contains data that might be tainted");
					}
				}
				break;
			}

			if (strncmp("mysqli_query", fname, len) == 0
					|| strncmp("mysql_query", fname, len) == 0
					|| strncmp("sqlite_query", fname, len) == 0
					|| strncmp("sqlite_single_query", fname, len) == 0 ) {
				zval *query = ZEND_CALL_ARG(ex, arg_count);
				if (IS_STRING == Z_TYPE_P(query) && TAINT_POSSIBLE(Z_STR_P(query))) {
					php_taint_error(NULL, "SQL statement contains data that might be tainted");
				}
				break;
			}

			if (strncmp("oci_parse", fname, len) == 0) {
				if (arg_count > 1) {
					zval *sql = ZEND_CALL_ARG(ex, 2);
					if (IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
						php_taint_error(NULL, "SQL statement contains data that might be tainted");
					}
				}
				break;
			}

			if (strncmp("passthru", fname, len) == 0
					|| strncmp("system", fname, len) == 0
					|| strncmp("exec", fname, len) == 0
					|| strncmp("shell_exec", fname, len) == 0
					|| strncmp("proc_open", fname, len) == 0 ) {
				zval *cmd = ZEND_CALL_ARG(ex, arg_count);
				if (IS_STRING == Z_TYPE_P(cmd) && TAINT_POSSIBLE(Z_STR_P(cmd))) {
					php_taint_error(NULL, "CMD statement contains data that might be tainted");
				}
				break;
			}
#if 0
			if (strncmp("escapeshellcmd", fname, len) == 0
					|| strncmp("htmlspecialchars", fname, len) == 0
					|| strncmp("escapeshellcmd", fname, len) == 0
					|| strncmp("addcslashes", fname, len) == 0
					|| strncmp("addslashes", fname, len) == 0
					|| strncmp("mysqli_escape_string", fname, len) == 0
					|| strncmp("mysql_real_escape_string", fname, len) == 0
					|| strncmp("mysql_escape_string", fname, len) == 0
					|| strncmp("sqlite_escape_string", fname, len) == 0) {
				zval *el;
				el = *((zval **) (p - (arg_count)));
				if (el && IS_STRING == Z_TYPE_P(el) && TAINT_POSSIBLE(el)) {
					TAINT_MARK(el, PHP_TAINT_MAGIC_NONE);
				}
				break;
			}
#endif
		} while (0);
	} else {
		do {
			const char *class_name = ZSTR_VAL(fbc->common.scope->name);
			size_t cname_len = ZSTR_LEN(fbc->common.scope->name);
			const char *fname = ZSTR_VAL(fbc->common.function_name);
			size_t len = ZSTR_LEN(fbc->common.function_name);

			if (strncmp("mysqli", class_name, cname_len) == 0) {
				if (strncmp("query", fname, len) == 0) {
					zval *sql = ZEND_CALL_ARG(ex, arg_count);
					if (IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
						php_taint_error(NULL, "SQL statement contains data that might be tainted");
					}
				}
#if 0
				else if (strncmp("escape_string", fname, len) == 0
						|| strncmp("real_escape_string", fname, len) == 0 ) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && TAINT_POSSIBLE(el)) {
						TAINT_MARK(el, PHP_TAINT_MAGIC_NONE);
					}
				}
#endif
				break;
			}

			if (strncmp("sqlitedatabase", class_name, cname_len) == 0) {
				if (strncmp("query", fname, len) == 0
						|| strncmp("singlequery", fname, len) == 0) {
					zval *sql = ZEND_CALL_ARG(ex, arg_count);
					if (IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
						php_taint_error(NULL, "SQL statement contains data that might be tainted");
					}
				}
				break;
			}

			if (strncmp("pdo", class_name, cname_len) == 0) {
				if (strncmp("query", fname, len) == 0
						|| strncmp("prepare", fname, len) == 0) {
					zval *sql = ZEND_CALL_ARG(ex, arg_count);
					if (IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
						php_taint_error(NULL, "SQL statement contains data that might be tainted");
					}
				}
#if 0
				else if (strncmp("quote", fname, len) == 0) {
					zval *el;
					el = *((zval **) (p - (arg_count)));
					if (el && IS_STRING == Z_TYPE_P(el) && TAINT_POSSIBLE(el)) {
						TAINT_MARK(el, PHP_TAINT_MAGIC_NONE);
					}
				}
#endif
				break;
			}
		} while (0);
	}
} /* }}} */

static int php_taint_fcall_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zend_execute_data *call = execute_data->call;
	zend_function *fbc = call->func;

	if (fbc->type == ZEND_INTERNAL_FUNCTION) {
		php_taint_fcall_check(call, opline, fbc);
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static void php_taint_register_handlers() /* {{{ */ {
	zend_set_user_opcode_handler(ZEND_ECHO, php_taint_echo_handler);
	zend_set_user_opcode_handler(ZEND_INCLUDE_OR_EVAL, php_taint_include_or_eval_handler);
	//zend_set_user_opcode_handler(ZEND_CONCAT, php_taint_concat_handler);
	//zend_set_user_opcode_handler(ZEND_ASSIGN_CONCAT, php_taint_assign_concat_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL, php_taint_fcall_handler);
	zend_set_user_opcode_handler(ZEND_DO_ICALL, php_taint_fcall_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, php_taint_fcall_handler);
} /* }}} */

static void php_taint_override_func(char *name, size_t len, php_func handler, php_func *stash) /* {{{ */ {
	zend_function *func;
	if ((func = zend_hash_str_find_ptr(CG(function_table), name, len)) != NULL) {
		if (stash) {
			*stash = func->internal_function.handler;
		}
		func->internal_function.handler = handler;
	}
} /* }}} */

static void php_taint_override_functions() /* {{{ */ {
	char f_join[]        = "join";
	char f_trim[]        = "trim";
	char f_split[]       = "split";
	char f_rtrim[]       = "rtrim";
	char f_ltrim[]       = "ltrim";
	char f_strval[]      = "strval";
	char f_strstr[]      = "strstr";
	char f_substr[]      = "substr";
	char f_sprintf[]     = "sprintf";
	char f_explode[]     = "explode";
	char f_implode[]     = "implode";
	char f_str_pad[]     = "str_pad";
	char f_vsprintf[]    = "vsprintf";
	char f_str_replace[] = "str_replace";
	char f_strtolower[] = "strtolower";
	char f_strtoupper[] = "strtoupper";

	php_taint_override_func(f_strval, sizeof(f_strval), PHP_FN(taint_strval), &TAINT_O_FUNC(strval));
	php_taint_override_func(f_sprintf, sizeof(f_sprintf), PHP_FN(taint_sprintf), &TAINT_O_FUNC(sprintf));
	php_taint_override_func(f_vsprintf, sizeof(f_vsprintf), PHP_FN(taint_vsprintf), &TAINT_O_FUNC(vsprintf));
	php_taint_override_func(f_explode, sizeof(f_explode), PHP_FN(taint_explode), &TAINT_O_FUNC(explode));
	php_taint_override_func(f_split, sizeof(f_split), PHP_FN(taint_explode), NULL);
	php_taint_override_func(f_implode, sizeof(f_implode), PHP_FN(taint_implode), &TAINT_O_FUNC(implode));
	php_taint_override_func(f_join, sizeof(f_join), PHP_FN(taint_implode), NULL);
	php_taint_override_func(f_trim, sizeof(f_trim), PHP_FN(taint_trim), &TAINT_O_FUNC(trim));
	php_taint_override_func(f_rtrim, sizeof(f_rtrim), PHP_FN(taint_rtrim), &TAINT_O_FUNC(rtrim));
	php_taint_override_func(f_ltrim, sizeof(f_ltrim), PHP_FN(taint_ltrim), &TAINT_O_FUNC(ltrim));
	php_taint_override_func(f_str_replace, sizeof(f_str_replace), PHP_FN(taint_str_replace), &TAINT_O_FUNC(str_replace));
	php_taint_override_func(f_str_pad, sizeof(f_str_pad), PHP_FN(taint_str_pad), &TAINT_O_FUNC(str_pad));
	php_taint_override_func(f_strstr, sizeof(f_strstr), PHP_FN(taint_strstr), &TAINT_O_FUNC(strstr));
	php_taint_override_func(f_strtolower, sizeof(f_strtolower), PHP_FN(taint_strtolower), &TAINT_O_FUNC(strtolower));
	php_taint_override_func(f_strtoupper, sizeof(f_strtoupper), PHP_FN(taint_strtoupper), &TAINT_O_FUNC(strtoupper));
	php_taint_override_func(f_substr, sizeof(f_substr), PHP_FN(taint_substr), &TAINT_O_FUNC(substr));

} /* }}} */

#ifdef COMPILE_DL_TAINT
ZEND_GET_MODULE(taint)
#endif

	/* {{{ proto string strval(mixed $value)
	*/
	PHP_FUNCTION(taint_strval) {
		zval *num;
		int tainted = 0;

		if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &num) == FAILURE) {
			return;
		}

		if (Z_TYPE_PP(num) == IS_STRING && TAINT_POSSIBLE(Z_STR_P(num))) {
			tainted = 1;
		}

		TAINT_O_FUNC(strval)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

		if (tainted && IS_STRING == Z_TYPE_P(return_value) 
				&& Z_STR_P(return_value) != Z_STR_P(num) && Z_STRLEN_P(return_value)) {
			TAINT_MARK(Z_STR_P(return_value));
		}
	}
/* }}} */

/* {{{ proto string sprintf(string $format, ...)
*/
PHP_FUNCTION(taint_sprintf) {
	zval *args;
	int i, argc, tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "+", &args, &argc) == FAILURE) {
		RETURN_FALSE;
	}

	for (i = 0; i < argc; i++) {
		if (IS_STRING == Z_TYPE(args[i]) && TAINT_POSSIBLE(Z_STR(args[i]))) {
			tainted = 1;
			break;
		}
	}

	TAINT_O_FUNC(sprintf)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string vsprintf(string $format, ...)
*/
PHP_FUNCTION(taint_vsprintf) {
	zval *args;
	zend_string *format;
	int i, tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sa", &format, &args) == FAILURE) {
		RETURN_FALSE;
	}

	do {
		zval *val;
		if (TAINT_POSSIBLE(format)) {
			tainted = 1;
			break;
		}

		ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(args), val) {
			if (IS_STRING == Z_TYPE_P(val) && TAINT_POSSIBLE(Z_STR_P(val))) {
				tainted = 1;
				break;
			}
		} ZEND_HASH_FOREACH_END();
	} while (0);

	TAINT_O_FUNC(vsprintf)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto array explode(string $separator, string $str[, int $limit])
*/
PHP_FUNCTION(taint_explode) {
	zend_string *str, *delim;
	zend_long limit = ZEND_LONG_MAX;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|l", &delim, &str, &limit) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(explode)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_ARRAY == Z_TYPE_P(return_value) && zend_hash_num_elements(Z_ARRVAL_P(return_value))) {
		php_taint_mark_strings(Z_ARRVAL_P(return_value));
	}
}
/* }}} */

/* {{{ proto string implode(string $separator, array $args)
*/
PHP_FUNCTION(taint_implode) {
	zval *op1, *op2;
	zval *target = NULL;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &op1, &op2) == FAILURE) {
		ZVAL_FALSE(return_value);
		WRONG_PARAM_COUNT;
	}

	if (IS_ARRAY == Z_TYPE_P(op1)) {
		target = op1;
	} else if(IS_ARRAY == Z_TYPE_P(op2)) {
		target = op2;
	}

	if (target) {
		zval *val;
		ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(target), val) {
			if (IS_STRING == Z_TYPE_P(val) && Z_STRLEN_P(val) && TAINT_POSSIBLE(Z_STR_P(val))) {
				tainted = 1;
				break;
			}
		} ZEND_HASH_FOREACH_END();
	}

	TAINT_O_FUNC(implode)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string trim(string $str)
*/
PHP_FUNCTION(taint_trim)
{
	zend_string *str, *what;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|S", &str, &what) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(trim)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && 
			Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string rtrim(string $str)
*/
PHP_FUNCTION(taint_rtrim)
{
	PHP_FN(taint_trim)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto string ltrim(string $str)
*/
PHP_FUNCTION(taint_ltrim)
{
	PHP_FN(taint_trim)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto string str_replace(mixed $search, mixed $replace, mixed $subject [, int &$count])
*/
PHP_FUNCTION(taint_str_replace)
{
	zval *str, *from, *len, *repl;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz|z", &str, &repl, &from, &len) == FAILURE) {
		return;
	}

	if (IS_STRING == Z_TYPE_P(repl) && TAINT_POSSIBLE(Z_STR_P(repl))) {
		tainted = 1;
	} else if (IS_STRING == Z_TYPE_P(from) && TAINT_POSSIBLE(Z_STR_P(from))) {
		tainted = 1;
	}

	TAINT_O_FUNC(str_replace)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string str_pad(string $input, int $pad_length[, string $pad_string = " "[, int $pad_type = STR_PAD_RIGHT]])
*/
PHP_FUNCTION(taint_str_pad)
{
	zend_string *input;
	zend_long pad_length;
	zend_string *pad_str = NULL;
	zend_long pad_type_val = 1;
	int	tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sl|Sl", &input, &pad_length, &pad_str, &pad_type_val) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(input)) {
		tainted = 1;
	} else if (pad_str && TAINT_POSSIBLE(pad_str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(str_pad)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string strstr(string $haystack, mixed $needle[, bool $part = false])
*/
PHP_FUNCTION(taint_strstr)
{
	zval *needle;
	zend_string *haystack;
	zend_bool part = 0;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sz|b", &haystack, &needle, &part) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(haystack)) {
		tainted = 1;
	}

	TAINT_O_FUNC(strstr)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) &&
			Z_STR_P(return_value) != haystack &&	Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string substr(string $string, int $start[, int $length])
*/
PHP_FUNCTION(taint_substr)
{
	zend_string *str;
	zend_long l = 0, f;
	int	tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sl|l", &str, &f, &l) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(substr)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) && 
			Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string strtolower(string $string)
*/
PHP_FUNCTION(taint_strtolower)
{
	zend_string *str;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &str) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(strtolower)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) &&
			Z_STR_P(return_value) != str	&& Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string strtoupper(string $string)
*/
PHP_FUNCTION(taint_strtoupper)
{
	zend_string *str;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &str) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(strtoupper)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) &&
			Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

static PHP_INI_MH(OnUpdateErrorLevel) /* {{{ */ {
	if (!new_value) {
		TAINT_G(error_level) = E_WARNING;
	} else {
		TAINT_G(error_level) = (int)atoi(ZSTR_VAL(new_value));
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

	/* {{{ proto bool taint(string $str[, string ...])
	*/
PHP_FUNCTION(taint)
{
	zval *args;
	int argc;
	int i;

	if (!TAINT_G(enable)) {
		RETURN_TRUE;
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "+", &args, &argc) == FAILURE) {
		return;
	}

	for (i = 0; i < argc; i++) {
		zval *el = &args[i];
		ZVAL_DEREF(el);
		if (IS_STRING == Z_TYPE_P(el) && Z_STRLEN_P(el) && !TAINT_POSSIBLE(Z_STR_P(el))) {
			TAINT_MARK(Z_STR_P(el));
		}
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool untaint(string $str[, string ...])
*/
PHP_FUNCTION(untaint)
{
	zval *args;
	int argc;
	int i;

	if (!TAINT_G(enable)) {
		RETURN_TRUE;
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "+", &args, &argc) == FAILURE) {
		return;
	}

	for (i=0; i<argc; i++) {
		if (IS_STRING == Z_TYPE(args[i]) && !TAINT_POSSIBLE(Z_STR(args[i]))) {
			TAINT_CLEAN(Z_STR(args[i]));
		}
	}

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

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &arg) == FAILURE) {
		return;
	}

	if (IS_STRING == Z_TYPE_P(arg) && TAINT_POSSIBLE(Z_STR_P(arg))) {
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

	if (!TAINT_G(enable)) {
		return SUCCESS;
	}

	php_taint_register_handlers();
	php_taint_override_functions();

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

	if (Z_TYPE(PG(http_globals)[TRACK_VARS_POST]) == IS_ARRAY) {
		php_taint_mark_strings(Z_ARRVAL(PG(http_globals)[TRACK_VARS_POST]));
	}

	if (Z_TYPE(PG(http_globals)[TRACK_VARS_GET]) == IS_ARRAY) {
		php_taint_mark_strings(Z_ARRVAL(PG(http_globals)[TRACK_VARS_GET]));
	}

	if (Z_TYPE(PG(http_globals)[TRACK_VARS_COOKIE]) == IS_ARRAY) {
		php_taint_mark_strings(Z_ARRVAL(PG(http_globals)[TRACK_VARS_COOKIE]));
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
	php_info_print_table_row(2, "Version", PHP_TAINT_VERSION);
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
