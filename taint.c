/*
   +----------------------------------------------------------------------+
   | Taint                                                                |
   +----------------------------------------------------------------------+
   | Copyright (c) 2012-2015 The PHP Group                                |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "SAPI.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_exceptions.h"
#if PHP_VERSION_ID >= 80400
#include "zend_frameless_function.h"
#include "zend_observer.h"
#endif
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_taint.h"

/* Indexed by opcode (NOT by registration order). */
static void *origin_opcode_handler[256];

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
	/* ZEND_MOD_CONFLICTS("xdebug") */
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
	php_func str_ireplace;
	php_func substr;
	php_func strtolower;
	php_func strtoupper;
	php_func dirname;
	php_func basename;
	php_func pathinfo;
} taint_origin_funcs;

#define TAINT_O_FUNC(m) (taint_origin_funcs.m)
/* }}} */

static void php_taint_mark_strings(zend_array *symbol_table) /* {{{ */ {
	zval *val;
	ZEND_HASH_FOREACH_VAL(symbol_table, val) {
		ZVAL_DEREF(val);
		if (Z_TYPE_P(val) == IS_ARRAY) {
			php_taint_mark_strings(Z_ARRVAL_P(val));
		} else if (IS_STRING == Z_TYPE_P(val) && Z_STRLEN_P(val)) {
			TAINT_MARK(Z_STR_P(val));
		}
	} ZEND_HASH_FOREACH_END();
} /* }}} */

/* Operand getters, adapted from zend_execute.c for use in user opcode
 * handlers. CONST operands are addressed relative to the opline that owns
 * them on 64bit builds (ZEND_USE_ABS_CONST_ADDR == 0), therefore every
 * getter takes an explicit opline pointer: pass `opline` for operands of
 * the current instruction and `opline + 1` for OP_DATA operands. */
static zval *php_taint_get_zval_ptr_tmpvar(zend_execute_data *execute_data, uint32_t var, taint_free_op *should_free) /* {{{ */ {
	zval *ret = EX_VAR(var);

	if (should_free) {
		*should_free = ret;
	}

	return ret;
}
/* }}} */

#ifndef CV_DEF_OF
#define CV_DEF_OF(i) (EX(func)->op_array.vars[i])
#endif

static zval *php_taint_get_zval_ptr_cv(zend_execute_data *execute_data, uint32_t var, int type, int force_ret) /* {{{ */ {
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		if (force_ret) {
			switch (type) {
				case BP_VAR_R:
				case BP_VAR_UNSET:
					zend_error(E_WARNING, "Undefined variable $%s", ZSTR_VAL(CV_DEF_OF(EX_VAR_TO_NUM(var))));
					/* break missing intentionally */
				case BP_VAR_IS:
					ret = &EG(uninitialized_zval);
					break;
				case BP_VAR_RW:
					zend_error(E_WARNING, "Undefined variable $%s", ZSTR_VAL(CV_DEF_OF(EX_VAR_TO_NUM(var))));
					/* break missing intentionally */
				case BP_VAR_W:
					ZVAL_NULL(ret);
					break;
			}
		} else {
			return NULL;
		}
	} else {
		ZVAL_DEREF(ret);
	}
	return ret;
}
/* }}} */

static zval *php_taint_get_zval_ptr(zend_execute_data *execute_data, const zend_op *opline, int op_type, znode_op op, taint_free_op *should_free, int type, int force_ret) /* {{{ */ {
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		return php_taint_get_zval_ptr_tmpvar(execute_data, op.var, should_free);
	} else {
		if (should_free) {
			*should_free = NULL;
		}
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline, op);
		} else if (op_type == IS_CV) {
			return php_taint_get_zval_ptr_cv(execute_data, op.var, type, force_ret);
		} else {
			return NULL;
		}
	}
}
/* }}} */

static zval *php_taint_get_zval_ptr_ptr_var(zend_execute_data *execute_data, uint32_t var, taint_free_op *should_free) /* {{{ */ {
	zval *ret = EX_VAR(var);

	if (EXPECTED(Z_TYPE_P(ret) == IS_INDIRECT)) {
		if (should_free) {
			*should_free = NULL;
		}
		ret = Z_INDIRECT_P(ret);
	} else if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		if (should_free) {
			*should_free = NULL;
		}
		ret = NULL;
	} else {
		if (should_free) {
			*should_free = ret;
		}
	}
	return ret;
}
/* }}} */

static zval *php_taint_get_zval_ptr_ptr(zend_execute_data *execute_data, const zend_op *opline, int op_type, znode_op op, taint_free_op *should_free, int type) /* {{{ */ {
	if (op_type == IS_CV) {
		if (should_free) {
			*should_free = NULL;
		}
		return php_taint_get_zval_ptr_cv(execute_data, op.var, type, 1);
	} else if (op_type == IS_VAR) {
		return php_taint_get_zval_ptr_ptr_var(execute_data, op.var, should_free);
	} else if (op_type == IS_UNUSED) {
		if (should_free) {
			*should_free = NULL;
		}
		return &EX(This);
	} else {
		ZEND_ASSERT(0);
		return NULL;
	}
}
/* }}} */

static void php_taint_error(const char *fname, const char *format, ...) /* {{{ */ {
	char *buffer, *msg;
	va_list args;

	va_start(args, format);
	vspprintf(&buffer, 0, format, args);
	spprintf(&msg, 0, "%s() [%s]: %s", get_active_function_name(), fname, buffer);
	efree(buffer);
	zend_error(TAINT_G(error_level), "%s", msg);
	efree(msg);
	va_end(args);
} /* }}} */

/* Call a previously installed user opcode handler (another extension that
 * registered before taint), used by inspection-style handlers which defer
 * execution to the engine. */
#define CALL_ORIGIN_HANDLER() do { \
		if (origin_opcode_handler[opline->opcode]) { \
			return ((user_opcode_handler_t)(origin_opcode_handler[opline->opcode]))(execute_data); \
		} \
	} while (0)

/* For handlers which execute the opcode themselves: give a previously
 * installed handler the chance to handle the opcode first; if it defers to
 * the engine (DISPATCH) or there is none, we execute it ourselves. Calling
 * the origin handler *after* executing would risk double execution. */
#define ORIGIN_PRECHECK() do { \
		if (origin_opcode_handler[opline->opcode]) { \
			int _taint_ret = ((user_opcode_handler_t)(origin_opcode_handler[opline->opcode]))(execute_data); \
			if (_taint_ret != ZEND_USER_OPCODE_DISPATCH) { \
				return _taint_ret; \
			} \
		} \
	} while (0)

#define TAINT_STR_TAINTED(zv) \
	((zv) != NULL && IS_STRING == Z_TYPE_P(zv) && TAINT_POSSIBLE(Z_STR_P(zv)))

static int php_taint_echo_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op1 = NULL;
	zval *op1;

	op1 = php_taint_get_zval_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 0);

	if (TAINT_STR_TAINTED(op1)) {
		if (opline->extended_value) {
			php_taint_error("print", "Attempt to print a string that might be tainted");
		} else {
			php_taint_error("echo", "Attempt to echo a string that might be tainted");
		}
	}

	/* Do NOT free operands: the default handler will re-fetch and free them. */
	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

#ifdef ZEND_EXIT
static int php_taint_exit_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op1 = NULL;
	zval *op1;

	op1 = php_taint_get_zval_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 0);

	if (TAINT_STR_TAINTED(op1)) {
		php_taint_error("exit", "Attempt to output a string that might be tainted");
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */
#endif

static int php_taint_init_dynamic_fcall_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op2 = NULL;
	zval *op2;

	op2 = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 0);

	if (op2) {
		if (IS_STRING == Z_TYPE_P(op2)) {
			if (TAINT_POSSIBLE(Z_STR_P(op2))) {
				php_taint_error("fcall", "Attempt to call a function which name might be tainted");
			}
		} else if (IS_ARRAY == Z_TYPE_P(op2)) {
			zval *cname = zend_hash_index_find(Z_ARRVAL_P(op2), 0);
			zval *mname = zend_hash_index_find(Z_ARRVAL_P(op2), 1);

			if (cname) {
				ZVAL_DEREF(cname);
			}
			if (mname) {
				ZVAL_DEREF(mname);
			}

			if (cname && IS_STRING == Z_TYPE_P(cname) && TAINT_POSSIBLE(Z_STR_P(cname))) {
				php_taint_error("fcall", "Attempt to call a method of a class which name might be tainted");
			} else if (mname && IS_STRING == Z_TYPE_P(mname) && TAINT_POSSIBLE(Z_STR_P(mname))) {
				php_taint_error("fcall", "Attempt to call a method which name might be tainted");
			}
		}
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_init_method_call_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op2 = NULL;
	zval *op2;

	op2 = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 0);

	if (TAINT_STR_TAINTED(op2)) {
		php_taint_error("fcall", "Attempt to call a method which name might be tainted");
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_include_or_eval_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	taint_free_op free_op1 = NULL;
	zval *op1;

	op1 = php_taint_get_zval_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 0);

	if (TAINT_STR_TAINTED(op1)) {
		switch (opline->extended_value) {
			case ZEND_INCLUDE_ONCE:
				php_taint_error("include_once", "File path contains data that might be tainted");
				break;
			case ZEND_REQUIRE_ONCE:
				php_taint_error("require_once", "File path contains data that might be tainted");
				break;
			case ZEND_INCLUDE:
				php_taint_error("include", "File path contains data that might be tainted");
				break;
			case ZEND_REQUIRE:
				php_taint_error("require", "File path contains data that might be tainted");
				break;
			case ZEND_EVAL:
				php_taint_error("eval", "Code contains data that might be tainted");
				break;
		}
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

/* Replicates ZEND_ROPE_END from zend_vm_execute.h (per op2-type ownership
 * semantics) and marks the result when any rope part is tainted. */
static int php_taint_rope_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zend_string **rope;
	zval *var, *result;
	taint_free_op free_op2 = NULL;
	uint32_t i, ext;
	int tainted = 0;
	size_t len = 0;

	ext = opline->extended_value;
	rope = (zend_string **)EX_VAR(opline->op1.var);

	if (opline->op2_type == IS_CONST) {
		var = RT_CONSTANT(opline, opline->op2);
		rope[ext] = Z_STR_P(var);
		if (UNEXPECTED(Z_REFCOUNTED_P(var))) {
			Z_ADDREF_P(var);
		}
	} else {
		var = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
		if (EXPECTED(Z_TYPE_P(var) == IS_STRING)) {
			if (opline->op2_type == IS_CV) {
				rope[ext] = zend_string_copy(Z_STR_P(var));
			} else {
				/* ownership of the string moves into the rope */
				rope[ext] = Z_STR_P(var);
				free_op2 = NULL;
			}
		} else {
			rope[ext] = zval_get_string_func(var);
			if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
				zval_ptr_dtor_nogc(free_op2);
			}
			if (UNEXPECTED(EG(exception))) {
				for (i = 0; i <= ext; i++) {
					zend_string_release_ex(rope[i], 0);
				}
				ZVAL_UNDEF(EX_VAR(opline->result.var));
				return ZEND_HANDLE_EXCEPTION;
			}
		}
	}

#ifdef ZSTR_COPYABLE_CONCAT_PROPERTIES
	uint32_t flags = ZSTR_COPYABLE_CONCAT_PROPERTIES;
#endif
	for (i = 0; i <= ext; i++) {
		if (TAINT_POSSIBLE(rope[i])) {
			tainted = 1;
		}
#ifdef ZSTR_COPYABLE_CONCAT_PROPERTIES
		flags &= ZSTR_GET_COPYABLE_CONCAT_PROPERTIES(rope[i]);
#endif
		len += ZSTR_LEN(rope[i]);
	}

	result = EX_VAR(opline->result.var);
	ZVAL_STR(result, zend_string_alloc(len, 0));
#ifdef ZSTR_COPYABLE_CONCAT_PROPERTIES
	GC_ADD_FLAGS(Z_STR_P(result), flags);
#endif

	char *target = Z_STRVAL_P(result);
	for (i = 0; i <= ext; i++) {
		memcpy(target, ZSTR_VAL(rope[i]), ZSTR_LEN(rope[i]));
		target += ZSTR_LEN(rope[i]);
		zend_string_release_ex(rope[i], 0);
	}
	*target = '\0';

	if (tainted && len) {
		TAINT_MARK(Z_STR_P(result));
	}

	execute_data->opline++;
	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

/* Executes ZEND_CONCAT/ZEND_FAST_CONCAT ourselves (the engine's string fast
 * paths do not preserve the taint bit). */
static int php_taint_concat_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *op1, *op2, *result;
	taint_free_op free_op1 = NULL, free_op2 = NULL;
	int tainted = 0;

	op1 = php_taint_get_zval_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 1);
	op2 = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);

	result = EX_VAR(opline->result.var);

	if (TAINT_STR_TAINTED(op1) || TAINT_STR_TAINTED(op2)) {
		tainted = 1;
	}

	if (UNEXPECTED(concat_function(result, op1, op2) == FAILURE)) {
		if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
			zval_ptr_dtor_nogc(free_op1);
		}
		if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
			zval_ptr_dtor_nogc(free_op2);
		}
		if (TAINT_RET_USED(opline)) {
			ZVAL_UNDEF(result);
		}
		return ZEND_HANDLE_EXCEPTION;
	}

	if (tainted && IS_STRING == Z_TYPE_P(result) && Z_STRLEN_P(result)) {
		TAINT_MARK(Z_STR_P(result));
	}

	if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
		zval_ptr_dtor_nogc(free_op1);
	}
	if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
		zval_ptr_dtor_nogc(free_op2);
	}

	execute_data->opline++;
	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

/* ZEND_ASSIGN_OP with ZEND_CONCAT: $a .= expr */
static int php_taint_binary_assign_op_helper(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *var_ptr, *value;
	taint_free_op free_op1 = NULL, free_op2 = NULL;
	int tainted = 0;

	value = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
	var_ptr = php_taint_get_zval_ptr_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);

	if (opline->op1_type == IS_VAR) {
		if (var_ptr == NULL || TAINT_ISERR(var_ptr)) {
			CALL_ORIGIN_HANDLER();
			return ZEND_USER_OPCODE_DISPATCH;
		}
	}

	if (UNEXPECTED(Z_TYPE_P(var_ptr) == IS_REFERENCE)) {
		/* typed references are not re-validated here (zend_binary_assign_op_typed_ref
		 * is private to the engine); acceptable divergence. */
		var_ptr = Z_REFVAL_P(var_ptr);
	}

	if (TAINT_STR_TAINTED(var_ptr) || TAINT_STR_TAINTED(value)) {
		tainted = 1;
	}

	if (UNEXPECTED(concat_function(var_ptr, var_ptr, value) == FAILURE)) {
		if (TAINT_RET_USED(opline)) {
			ZVAL_UNDEF(EX_VAR(opline->result.var));
		}
	} else {
		if (TAINT_RET_USED(opline)) {
			ZVAL_COPY(EX_VAR(opline->result.var), var_ptr);
		}
		if (tainted && IS_STRING == Z_TYPE_P(var_ptr) && Z_STRLEN_P(var_ptr)) {
			TAINT_MARK(Z_STR_P(var_ptr));
		}
	}

	if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
		zval_ptr_dtor_nogc(free_op2);
	}
	if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
		zval_ptr_dtor_nogc(free_op1);
	}

	if (UNEXPECTED(EG(exception))) {
		return ZEND_HANDLE_EXCEPTION;
	}
	execute_data->opline++;
	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

/* Port of zend_assign_op_overloaded_property (private in the engine) for
 * PHP 8 object handler signatures. */
static void php_taint_assign_op_overloaded_property(zend_object *zobj, zend_string *name, void **cache_slot, zval *value, zval *result) /* {{{ */ {
	zval *z;
	zval rv;
	zval *zptr;
	int tainted = 0;

	if (zobj->handlers->read_property &&
		(z = zobj->handlers->read_property(zobj, name, BP_VAR_R, cache_slot, &rv)) != NULL) {
		if (EG(exception)) {
			return;
		}
		zptr = z;
		ZVAL_DEREF(z);
		SEPARATE_ZVAL_NOREF(z);
		if (TAINT_STR_TAINTED(z) || TAINT_STR_TAINTED(value)) {
			tainted = 1;
		}
		if (UNEXPECTED(concat_function(z, z, value) == FAILURE)) {
			zval_ptr_dtor(zptr);
			if (result) {
				ZVAL_UNDEF(result);
			}
			return;
		}
		zobj->handlers->write_property(zobj, name, z, cache_slot);
		if (result) {
			ZVAL_COPY(result, z);
		}
		if (tainted && Z_TYPE_P(z) == IS_STRING && Z_STRLEN_P(z)) {
			TAINT_MARK(Z_STR_P(z));
		}
		zval_ptr_dtor(zptr);
	} else {
		if (result) {
			ZVAL_NULL(result);
		}
	}
}
/* }}} */

/* Port of zend_binary_assign_op_obj_dim (private in the engine) for PHP 8
 * object handler signatures: $obj[dim] .= value */
static void php_taint_binary_assign_op_obj_dim(zend_object *zobj, zval *property, zval *value, zval *result) /* {{{ */ {
	zval *z;
	zval rv, res;
	int tainted = 0;

	if (zobj->handlers->read_dimension &&
		(z = zobj->handlers->read_dimension(zobj, property, BP_VAR_R, &rv)) != NULL) {

		if (EG(exception)) {
			return;
		}

		{
			zval *zv = z;
			ZVAL_DEREF(zv);
			if (TAINT_STR_TAINTED(zv) || TAINT_STR_TAINTED(value)) {
				tainted = 1;
			}

			if (UNEXPECTED(concat_function(&res, zv, value) == FAILURE)) {
				if (z == &rv) {
					zval_ptr_dtor(&rv);
				}
				if (result) {
					ZVAL_UNDEF(result);
				}
				return;
			}
		}

		zobj->handlers->write_dimension(zobj, property, &res);
		if (z == &rv) {
			zval_ptr_dtor(&rv);
		}
		if (result) {
			ZVAL_COPY(result, &res);
		}
		if (tainted && Z_TYPE(res) == IS_STRING && Z_STRLEN(res)) {
			TAINT_MARK(Z_STR(res));
		}
		zval_ptr_dtor(&res);
	} else {
		zend_throw_error(NULL, "Cannot use object as array");
		if (result) {
			ZVAL_UNDEF(result);
		}
	}
}
/* }}} */

/* BP_VAR_RW dimension fetch on arrays (adapted from zend_execute.c with
 * PHP 8.x diagnostics). */
static zval *php_taint_fetch_dimension_address_inner(HashTable *ht, const zval *dim, int dim_type) /* {{{ */ {
	zval *retval;
	zend_string *offset_key;
	zend_ulong hval;

try_again:
	if (EXPECTED(Z_TYPE_P(dim) == IS_LONG)) {
		hval = Z_LVAL_P(dim);
num_index:
		retval = zend_hash_index_find(ht, hval);
		if (UNEXPECTED(retval == NULL)) {
			retval = zend_undefined_offset_write(ht, hval);
		}
	} else if (EXPECTED(Z_TYPE_P(dim) == IS_STRING)) {
		offset_key = Z_STR_P(dim);
		if (dim_type != IS_CONST) {
			if (ZEND_HANDLE_NUMERIC(offset_key, hval)) {
				goto num_index;
			}
		}
str_index:
		retval = zend_hash_find(ht, offset_key);
		if (UNEXPECTED(retval == NULL)) {
			retval = zend_undefined_index_write(ht, offset_key);
		}
	} else {
		switch (Z_TYPE_P(dim)) {
			case IS_NULL:
				/* Deprecated: using null as offset, engine warns elsewhere */
				offset_key = ZSTR_EMPTY_ALLOC();
				goto str_index;
			case IS_DOUBLE:
				hval = zend_dval_to_lval_safe(Z_DVAL_P(dim));
				goto num_index;
			case IS_RESOURCE:
				zend_use_resource_as_offset(dim);
				hval = Z_RES_HANDLE_P(dim);
				goto num_index;
			case IS_FALSE:
				hval = 0;
				goto num_index;
			case IS_TRUE:
				hval = 1;
				goto num_index;
			case IS_REFERENCE:
				dim = Z_REFVAL_P(dim);
				goto try_again;
			default:
				zend_illegal_container_offset(ZSTR_KNOWN(ZEND_STR_ARRAY), dim, BP_VAR_RW);
				retval = NULL;
		}
	}
	return retval;
}
/* }}} */

/* ZEND_ASSIGN_DIM_OP with ZEND_CONCAT: $a[dim] .= expr / $a[] .= expr */
static int php_taint_binary_assign_op_dim_helper(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *container, *dim = NULL, *value, *var_ptr;
	taint_free_op free_op1 = NULL, free_op2 = NULL, free_op_data = NULL;
	zval *result = TAINT_RET_USED(opline) ? EX_VAR(opline->result.var) : NULL;
	int tainted = 0;

	container = php_taint_get_zval_ptr_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);
	if ((opline->op1_type == IS_UNUSED && Z_OBJ_P(container) == NULL)
			|| (opline->op1_type == IS_VAR && (container == NULL || TAINT_ISERR(container)))) {
		CALL_ORIGIN_HANDLER();
		return ZEND_USER_OPCODE_DISPATCH;
	}

	if (opline->op2_type != IS_UNUSED) {
		dim = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
	}
	value = php_taint_get_zval_ptr(execute_data, opline + 1, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);

	if (EXPECTED(Z_TYPE_P(container) == IS_REFERENCE)) {
		container = Z_REFVAL_P(container);
	}

	if (opline->op1_type == IS_UNUSED || Z_TYPE_P(container) == IS_OBJECT) {
		zend_object *zobj = Z_OBJ_P(container);

		if (opline->op2_type == IS_CONST && dim && Z_EXTRA_P(dim) == ZEND_EXTRA_VALUE) {
			dim++;
		}
		php_taint_binary_assign_op_obj_dim(zobj, dim, value, result);
	} else if (EXPECTED(Z_TYPE_P(container) == IS_ARRAY)) {
dim_op_array:
		SEPARATE_ARRAY(container);
		if (dim == NULL) {
			var_ptr = zend_hash_next_index_insert(Z_ARRVAL_P(container), &EG(uninitialized_zval));
			if (UNEXPECTED(var_ptr == NULL)) {
				zend_cannot_add_element();
				goto dim_op_ret_null;
			}
		} else {
			var_ptr = php_taint_fetch_dimension_address_inner(Z_ARRVAL_P(container), dim, opline->op2_type);
			if (UNEXPECTED(var_ptr == NULL)) {
				goto dim_op_ret_null;
			}
		}

		if (UNEXPECTED(Z_ISREF_P(var_ptr))) {
			/* typed references are not re-validated (engine-private helper) */
			var_ptr = Z_REFVAL_P(var_ptr);
		}

		if (TAINT_STR_TAINTED(var_ptr) || TAINT_STR_TAINTED(value)) {
			tainted = 1;
		}

		if (UNEXPECTED(concat_function(var_ptr, var_ptr, value) == FAILURE)) {
			if (result) {
				ZVAL_UNDEF(result);
			}
		} else {
			if (result) {
				ZVAL_COPY(result, var_ptr);
			}
			if (tainted && IS_STRING == Z_TYPE_P(var_ptr) && Z_STRLEN_P(var_ptr)) {
				TAINT_MARK(Z_STR_P(var_ptr));
			}
		}
	} else if (EXPECTED(Z_TYPE_P(container) <= IS_FALSE)) {
		uint8_t old_type = Z_TYPE_P(container);
		HashTable *ht = zend_new_array(8);

		ZVAL_ARR(container, ht);
		if (UNEXPECTED(old_type == IS_FALSE)) {
			GC_ADDREF(ht);
			zend_false_to_array_deprecated();
			if (UNEXPECTED(GC_DELREF(ht) == 0)) {
				zend_array_destroy(ht);
				ZVAL_NULL(container);
				goto dim_op_ret_null;
			}
		}
		goto dim_op_array;
	} else {
		if (Z_TYPE_P(container) == IS_STRING) {
			zend_throw_error(NULL, "Cannot use assign-op operators with string offsets");
		} else {
			zend_throw_error(NULL, "Cannot use a scalar value as an array");
		}
dim_op_ret_null:
		if (result) {
			ZVAL_UNDEF(result);
		}
	}

	if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
		zval_ptr_dtor_nogc(free_op2);
	}
	if (((opline + 1)->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op_data) {
		zval_ptr_dtor_nogc(free_op_data);
	}
	if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
		zval_ptr_dtor_nogc(free_op1);
	}

	if (UNEXPECTED(EG(exception))) {
		return ZEND_HANDLE_EXCEPTION;
	}
	/* assign_dim_op spans two opcodes (instruction + OP_DATA) */
	execute_data->opline += 2;
	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

/* ZEND_ASSIGN_OBJ_OP with ZEND_CONCAT: $obj->prop .= expr */
static int php_taint_binary_assign_op_obj_helper(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *object, *property, *value, *zptr;
	taint_free_op free_op1 = NULL, free_op2 = NULL, free_op_data = NULL;
	void *_cache_slot[3] = {0};
	void **cache_slot;
	zend_object *zobj;
	zend_string *name = NULL, *tmp_name = NULL;
	zval *result = TAINT_RET_USED(opline) ? EX_VAR(opline->result.var) : NULL;
	int tainted = 0;

	object = php_taint_get_zval_ptr_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_RW);
	if ((opline->op1_type == IS_UNUSED && Z_OBJ_P(object) == NULL)
			|| (opline->op1_type == IS_VAR && (object == NULL || TAINT_ISERR(object)))) {
		CALL_ORIGIN_HANDLER();
		return ZEND_USER_OPCODE_DISPATCH;
	}

	property = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
	value = php_taint_get_zval_ptr(execute_data, opline + 1, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);

	do {
		if (UNEXPECTED(Z_TYPE_P(object) != IS_OBJECT)) {
			if (Z_ISREF_P(object) && Z_TYPE_P(Z_REFVAL_P(object)) == IS_OBJECT) {
				object = Z_REFVAL_P(object);
				goto taint_assign_op_object;
			}
			/* PHP 8 no longer creates a stdClass from empty values, it throws */
			if (opline->op2_type == IS_CONST && IS_STRING == Z_TYPE_P(property)) {
				zend_throw_error(NULL, "Attempt to assign property \"%s\" on %s",
					Z_STRVAL_P(property), zend_get_type_by_const(Z_TYPE_P(object)));
			} else {
				zend_throw_error(NULL, "Attempt to assign property on %s",
					zend_get_type_by_const(Z_TYPE_P(object)));
			}
			if (result) {
				ZVAL_UNDEF(result);
			}
			break;
		}

taint_assign_op_object:
		zobj = Z_OBJ_P(object);
		if (opline->op2_type == IS_CONST) {
			name = Z_STR_P(property);
			cache_slot = CACHE_ADDR((opline + 1)->extended_value);
		} else {
			name = zval_try_get_tmp_string(property, &tmp_name);
			if (UNEXPECTED(name == NULL)) {
				if (result) {
					ZVAL_UNDEF(result);
				}
				break;
			}
			cache_slot = _cache_slot;
		}

		if (EXPECTED((zptr = zobj->handlers->get_property_ptr_ptr(zobj, name, BP_VAR_RW, cache_slot)) != NULL)) {
			if (UNEXPECTED(Z_ISERROR_P(zptr))) {
				if (result) {
					ZVAL_NULL(result);
				}
			} else {
				if (UNEXPECTED(Z_ISREF_P(zptr))) {
					/* typed references are not re-validated (engine-private helper) */
					zptr = Z_REFVAL_P(zptr);
				}
				/* typed properties are not re-validated either (acceptable divergence) */

				if (TAINT_STR_TAINTED(zptr) || TAINT_STR_TAINTED(value)) {
					tainted = 1;
				}

				if (UNEXPECTED(concat_function(zptr, zptr, value) == FAILURE)) {
					if (result) {
						ZVAL_UNDEF(result);
					}
				} else {
					if (result) {
						ZVAL_COPY(result, zptr);
					}
					if (tainted && IS_STRING == Z_TYPE_P(zptr) && Z_STRLEN_P(zptr)) {
						TAINT_MARK(Z_STR_P(zptr));
					}
				}
			}
		} else {
			php_taint_assign_op_overloaded_property(zobj, name, cache_slot, value, result);
		}

		if (opline->op2_type != IS_CONST) {
			zend_tmp_string_release(tmp_name);
		}
	} while (0);

	if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
		zval_ptr_dtor_nogc(free_op2);
	}
	if (((opline + 1)->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op_data) {
		zval_ptr_dtor_nogc(free_op_data);
	}
	if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
		zval_ptr_dtor_nogc(free_op1);
	}

	if (UNEXPECTED(EG(exception))) {
		return ZEND_HANDLE_EXCEPTION;
	}
	/* assign_obj_op spans two opcodes (instruction + OP_DATA) */
	execute_data->opline += 2;
	return ZEND_USER_OPCODE_CONTINUE;
}
/* }}} */

static int php_taint_assign_op_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;

	if (UNEXPECTED(opline->extended_value == ZEND_CONCAT)) {
		ORIGIN_PRECHECK();
		return php_taint_binary_assign_op_helper(execute_data);
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_assign_dim_op_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;

	if (UNEXPECTED(opline->extended_value == ZEND_CONCAT)) {
		ORIGIN_PRECHECK();
		return php_taint_binary_assign_op_dim_helper(execute_data);
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int php_taint_assign_obj_op_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;

	if (UNEXPECTED(opline->extended_value == ZEND_CONCAT)) {
		ORIGIN_PRECHECK();
		return php_taint_binary_assign_op_obj_helper(execute_data);
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static void php_taint_fcall_check(zend_execute_data *ex, const zend_op *opline, zend_function *fbc) /* {{{ */ {
	int arg_count = ZEND_CALL_NUM_ARGS(ex);

	if (!arg_count && !zend_string_equals_literal(fbc->common.function_name, "exit")) {
		return;
	}

	if (fbc->common.scope == NULL) {
		zend_string *fname = fbc->common.function_name;
		if (zend_string_equals_literal(fname, "print_r")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to print_r data that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "var_dump")) {
			uint32_t i;
			for (i = 0; i < arg_count; i++) {
				zval *p = ZEND_CALL_ARG(ex, i + 1);
				if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
					php_taint_error(ZSTR_VAL(fname), "Attempt to var_dump data that might be tainted");
					break;
				}
			}
		} else if (zend_string_equals_literal(fname, "var_export")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to var_export data that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "exit") ||
				zend_string_equals_literal(fname, "die")) {
			/* since PHP 8.5 exit/die are regular internal functions */
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to output a string that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "fopen")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to open a file which path might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "unlink")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to unlink a file which path might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "file") ||
				zend_string_equals_literal(fname, "readfile") ||
				zend_string_equals_literal(fname, "file_get_contents") ||
				zend_string_equals_literal(fname, "highlight_file") ||
				zend_string_equals_literal(fname, "show_source")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to read a file which path might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "opendir")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to open a directory which path might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "printf")) {
			/* the format string is argument 1 and is emitted as-is when no
			 * values are given, so it is checked like any other argument */
			uint32_t i;
			for (i = 0; i < arg_count; i++) {
				zval *p = ZEND_CALL_ARG(ex, i + 1);
				if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
					php_taint_error(ZSTR_VAL(fname), "%dth argument contains data that might be tainted", i + 1);
					break;
				}
			}
		} else if (zend_string_equals_literal(fname, "vprintf")) {
			zval *fmt = ZEND_CALL_ARG(ex, 1);
			if (fmt && IS_STRING == Z_TYPE_P(fmt) && TAINT_POSSIBLE(Z_STR_P(fmt))) {
				php_taint_error(ZSTR_VAL(fname), "1th argument contains data that might be tainted");
			} else if (arg_count > 1) {
				zend_string *key;
				zend_long idx;
				zval *val, *p = ZEND_CALL_ARG(ex, 2);
				if (IS_ARRAY == Z_TYPE_P(p)) {
					ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(p), idx, key, val) {
						ZVAL_DEREF(val);
						if (IS_STRING == Z_TYPE_P(val) && TAINT_POSSIBLE(Z_STR_P(val))) {
							if (key) {
								php_taint_error(ZSTR_VAL(fname), "Second argument contains data(index:%s) that might be tainted", ZSTR_VAL(key));
							} else {
								php_taint_error(ZSTR_VAL(fname), "Second argument contains data(index:%ld) that might be tainted", idx);
							}
							break;
						}
					} ZEND_HASH_FOREACH_END();
				}
			}
		} else if (zend_string_equals_literal(fname, "file_put_contents") ||
				zend_string_equals_literal(fname, "fwrite") ||
				zend_string_equals_literal(fname, "fputs")) {
			zval *fp = ZEND_CALL_ARG(ex, 1);

			if (fp && IS_STRING == Z_TYPE_P(fp)) {
				if (TAINT_POSSIBLE(Z_STR_P(fp))) {
					php_taint_error(ZSTR_VAL(fname), "Attempt to write a file which path might be tainted");
				} else if (zend_string_equals_literal(Z_STR_P(fp), "php://output") && arg_count > 1) {
					zval *str = ZEND_CALL_ARG(ex, 2);
					if (str && IS_STRING == Z_TYPE_P(str) && TAINT_POSSIBLE(Z_STR_P(str))) {
						php_taint_error(ZSTR_VAL(fname), "Attempt to output data that might be tainted");
					}
				}
			}
		} else if (zend_string_equals_literal(fname, "header")) {
			zval *header = ZEND_CALL_ARG(ex, 1);
			if (header && IS_STRING == Z_TYPE_P(header) && TAINT_POSSIBLE(Z_STR_P(header))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to send a header that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "unserialize")) {
			/* TODO: allow_classes? */
			zval *str = ZEND_CALL_ARG(ex, 1);
			if (str && IS_STRING == Z_TYPE_P(str) && TAINT_POSSIBLE(Z_STR_P(str))) {
				php_taint_error(ZSTR_VAL(fname), "Attempt to unserialize a string that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "mysqli_query") ||
				zend_string_equals_literal(fname, "mysqli_prepare") ||
				zend_string_equals_literal(fname, "mysqli_real_query") ||
				zend_string_equals_literal(fname, "mysqli_multi_query") ||
				zend_string_equals_literal(fname, "mysql_query") ||
				zend_string_equals_literal(fname, "sqlite_query") ||
				zend_string_equals_literal(fname, "sqlite_single_query") ||
				zend_string_equals_literal(fname, "pg_query") ||
				zend_string_equals_literal(fname, "pg_send_query")) {
			zval *query = ZEND_CALL_ARG(ex, arg_count);
			if (query && IS_STRING == Z_TYPE_P(query) && TAINT_POSSIBLE(Z_STR_P(query))) {
				php_taint_error(ZSTR_VAL(fname), "SQL statement contains data that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "oci_parse")) {
			if (arg_count > 1) {
				zval *sql = ZEND_CALL_ARG(ex, 2);
				if (sql && IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
					php_taint_error(ZSTR_VAL(fname), "SQL statement contains data that might be tainted");
				}
			}
		} else if (zend_string_equals_literal(fname, "preg_replace_callback")) {
			if (arg_count > 1) {
				zval *callback = ZEND_CALL_ARG(ex, 2);
				if (callback && IS_STRING == Z_TYPE_P(callback)) {
					if (TAINT_POSSIBLE(Z_STR_P(callback))) {
						php_taint_error(ZSTR_VAL(fname), "Callback name contains data that might be tainted");
					}
				} else if (callback && IS_ARRAY == Z_TYPE_P(callback)) {
					zval *cname = zend_hash_index_find(Z_ARRVAL_P(callback), 0);
					zval *mname = zend_hash_index_find(Z_ARRVAL_P(callback), 1);

					if (cname) {
						ZVAL_DEREF(cname);
					}
					if (mname) {
						ZVAL_DEREF(mname);
					}

					if (cname && IS_STRING == Z_TYPE_P(cname) && TAINT_POSSIBLE(Z_STR_P(cname))) {
						php_taint_error(ZSTR_VAL(fname), "Callback class name contains data that might be tainted");
					} else if (mname && IS_STRING == Z_TYPE_P(mname) && TAINT_POSSIBLE(Z_STR_P(mname))) {
						php_taint_error(ZSTR_VAL(fname), "Callback method name contains data that might be tainted");
					}
				}
			}
		} else if (zend_string_equals_literal(fname, "passthru") ||
				zend_string_equals_literal(fname, "system") ||
				zend_string_equals_literal(fname, "exec") ||
				zend_string_equals_literal(fname, "shell_exec") ||
				zend_string_equals_literal(fname, "proc_open") ||
				zend_string_equals_literal(fname, "popen")) {
			/* the command is always the first argument */
			zval *cmd = ZEND_CALL_ARG(ex, 1);
			if (cmd && IS_STRING == Z_TYPE_P(cmd) && TAINT_POSSIBLE(Z_STR_P(cmd))) {
				php_taint_error(ZSTR_VAL(fname), "CMD statement contains data that might be tainted");
			}
		} else if (zend_string_equals_literal(fname, "setcookie") ||
				zend_string_equals_literal(fname, "setrawcookie")) {
			/* name and value both end up in the Set-Cookie header */
			uint32_t i;
			for (i = 1; i <= 2 && i <= arg_count; i++) {
				zval *p = ZEND_CALL_ARG(ex, i);
				if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
					php_taint_error(ZSTR_VAL(fname), "%dth argument contains data that might be tainted", i);
					break;
				}
			}
		} else if (zend_string_equals_literal(fname, "mail")) {
			/* to, subject, additional_params and additional_headers are
			 * injection vectors; the message body is content, not checked */
			static const uint32_t checked[] = {1, 2, 4, 5};
			uint32_t i;
			for (i = 0; i < sizeof(checked)/sizeof(uint32_t); i++) {
				if (checked[i] <= arg_count) {
					zval *p = ZEND_CALL_ARG(ex, checked[i]);
					if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
						php_taint_error(ZSTR_VAL(fname), "%dth argument contains data that might be tainted", checked[i]);
						break;
					}
				}
			}
		} else if (zend_string_equals_literal(fname, "copy") ||
				zend_string_equals_literal(fname, "rename") ||
				zend_string_equals_literal(fname, "move_uploaded_file")) {
			uint32_t i;
			for (i = 1; i <= 2 && i <= arg_count; i++) {
				zval *p = ZEND_CALL_ARG(ex, i);
				if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
					php_taint_error(ZSTR_VAL(fname), "%s path contains data that might be tainted", i == 1 ? "Source" : "Destination");
					break;
				}
			}
		} else if (zend_string_equals_literal(fname, "mkdir") ||
				zend_string_equals_literal(fname, "rmdir") ||
				zend_string_equals_literal(fname, "touch")) {
			zval *p = ZEND_CALL_ARG(ex, 1);
			if (p && IS_STRING == Z_TYPE_P(p) && TAINT_POSSIBLE(Z_STR_P(p))) {
				php_taint_error(ZSTR_VAL(fname), "Path contains data that might be tainted");
			}
		}
	} else {
		char mname[64];
		zend_string *class_name = fbc->common.scope->name;
		zend_string *fname = fbc->common.function_name;

		if (zend_string_equals_literal(class_name, "mysqli")) {
			if (zend_string_equals_literal(fname, "query") ||
				zend_string_equals_literal(fname, "prepare") ||
				zend_string_equals_literal(fname, "real_query") ||
				zend_string_equals_literal(fname, "multi_query")) {
				zval *sql = ZEND_CALL_ARG(ex, 1);
				if (sql && IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
					snprintf(mname, sizeof(mname), "%s::%s", "mysqli", ZSTR_VAL(fname));
					php_taint_error(mname, "SQL statement contains data that might be tainted");
				}
			}
		} else if (zend_string_equals_literal(class_name, "PDO")) {
			if (zend_string_equals_literal(fname, "query") ||
				zend_string_equals_literal(fname, "prepare") ||
				zend_string_equals_literal(fname, "exec")) {
				zval *sql = ZEND_CALL_ARG(ex, arg_count);
				if (sql && IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
					snprintf(mname, sizeof(mname), "%s::%s", "PDO", ZSTR_VAL(fname));
					php_taint_error(mname, "SQL statement contains data that might be tainted");
				}
			}
		} else if (zend_string_equals_literal(class_name, "SQLite3")) {
			if (zend_string_equals_literal(fname, "query") ||
				zend_string_equals_literal(fname, "prepare") ||
				zend_string_equals_literal(fname, "exec")) {
				zval *sql = ZEND_CALL_ARG(ex, arg_count);
				if (sql && IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
					snprintf(mname, sizeof(mname), "%s::%s", "SQLite3", ZSTR_VAL(fname));
					php_taint_error(mname, "SQL statement contains data that might be tainted");
				}
			}
		} else if (zend_string_equals_literal(class_name, "sqlitedatabase")) {
			if (zend_string_equals_literal(fname, "query") ||
				zend_string_equals_literal(fname, "singlequery")) {
				zval *sql = ZEND_CALL_ARG(ex, arg_count);
				if (sql && IS_STRING == Z_TYPE_P(sql) && TAINT_POSSIBLE(Z_STR_P(sql))) {
					snprintf(mname, sizeof(mname), "%s::%s", "sqlitedatabase", ZSTR_VAL(fname));
					php_taint_error(mname, "SQL statement contains data that might be tainted");
				}
			}
		}
	}
} /* }}} */

static int php_taint_fcall_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zend_execute_data *call = execute_data->call;
	zend_function *fbc = call ? call->func : NULL;

	if (fbc && fbc->type == ZEND_INTERNAL_FUNCTION) {
		php_taint_fcall_check(call, opline, fbc);
	}

	CALL_ORIGIN_HANDLER();
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

/* Taint custom opcode handlers {{{ */
typedef struct {
	zend_uchar opcode;
	void      *handler;
} taint_custom_handler;

#if PHP_VERSION_ID >= 80400
static int php_taint_flic_handler(zend_execute_data *execute_data);
#endif

static const taint_custom_handler override_opcode_handlers[] = {
	{ ZEND_ECHO, php_taint_echo_handler },
#ifdef ZEND_EXIT
	{ ZEND_EXIT, php_taint_exit_handler },
#endif
	{ ZEND_INIT_USER_CALL, php_taint_init_dynamic_fcall_handler },
	{ ZEND_INIT_DYNAMIC_CALL, php_taint_init_dynamic_fcall_handler },
	{ ZEND_INIT_METHOD_CALL, php_taint_init_method_call_handler },
	{ ZEND_INCLUDE_OR_EVAL, php_taint_include_or_eval_handler },
	{ ZEND_CONCAT, php_taint_concat_handler },
	{ ZEND_FAST_CONCAT, php_taint_concat_handler },
	{ ZEND_ASSIGN_OP, php_taint_assign_op_handler },
	{ ZEND_ASSIGN_DIM_OP, php_taint_assign_dim_op_handler },
	{ ZEND_ASSIGN_OBJ_OP, php_taint_assign_obj_op_handler },
	{ ZEND_ROPE_END, php_taint_rope_handler },
	{ ZEND_DO_FCALL, php_taint_fcall_handler },
	{ ZEND_DO_ICALL, php_taint_fcall_handler },
	{ ZEND_DO_UCALL, php_taint_fcall_handler },
	{ ZEND_DO_FCALL_BY_NAME, php_taint_fcall_handler },
#if PHP_VERSION_ID >= 80400
	{ ZEND_FRAMELESS_ICALL_0, php_taint_flic_handler },
	{ ZEND_FRAMELESS_ICALL_1, php_taint_flic_handler },
	{ ZEND_FRAMELESS_ICALL_2, php_taint_flic_handler },
	{ ZEND_FRAMELESS_ICALL_3, php_taint_flic_handler },
#endif
};
/* }}} */

static void php_taint_register_handlers(void) /* {{{ */ {
	size_t idx;
	for (idx = 0; idx < sizeof(override_opcode_handlers)/sizeof(taint_custom_handler); idx++) {
		zend_uchar opcode = override_opcode_handlers[idx].opcode;
		origin_opcode_handler[opcode] = (void*)zend_get_user_opcode_handler(opcode);
	}
	for (idx = 0; idx < sizeof(override_opcode_handlers)/sizeof(taint_custom_handler); idx++) {
		zend_set_user_opcode_handler(override_opcode_handlers[idx].opcode, (user_opcode_handler_t)override_opcode_handlers[idx].handler);
	}
} /* }}} */

static void php_taint_override_func(const char *name, php_func handler, php_func *stash) /* {{{ */ {
	zend_function *func;
	if ((func = zend_hash_str_find_ptr(CG(function_table), name, strlen(name))) != NULL) {
		if (stash) {
			*stash = func->internal_function.handler;
		}
		fprintf(stderr, "[taint_dbg] override %s old=%p new=%p\n", name, (void*)func->internal_function.handler, (void*)handler);
		func->internal_function.handler = handler;
	} else {
		fprintf(stderr, "[taint_dbg] override %s NOT FOUND\n", name);
	}
} /* }}} */

static void php_taint_override_functions(void) /* {{{ */ {
	const char *f_join         = "join";
	const char *f_trim         = "trim";
	const char *f_rtrim        = "rtrim";
	const char *f_ltrim        = "ltrim";
	const char *f_strval       = "strval";
	const char *f_strstr       = "strstr";
	const char *f_substr       = "substr";
	const char *f_sprintf      = "sprintf";
	const char *f_explode      = "explode";
	const char *f_implode      = "implode";
	const char *f_str_pad      = "str_pad";
	const char *f_vsprintf     = "vsprintf";
	const char *f_str_replace  = "str_replace";
	const char *f_str_ireplace = "str_ireplace";
	const char *f_strtolower   = "strtolower";
	const char *f_strtoupper   = "strtoupper";
	const char *f_dirname      = "dirname";
	const char *f_basename     = "basename";
	const char *f_pathinfo     = "pathinfo";

	php_taint_override_func(f_strval, PHP_FN(taint_strval), &TAINT_O_FUNC(strval));
	php_taint_override_func(f_sprintf, PHP_FN(taint_sprintf), &TAINT_O_FUNC(sprintf));
	php_taint_override_func(f_vsprintf, PHP_FN(taint_vsprintf), &TAINT_O_FUNC(vsprintf));
	php_taint_override_func(f_explode, PHP_FN(taint_explode), &TAINT_O_FUNC(explode));
	php_taint_override_func(f_implode, PHP_FN(taint_implode), &TAINT_O_FUNC(implode));
	php_taint_override_func(f_join, PHP_FN(taint_implode), NULL);
	php_taint_override_func(f_trim, PHP_FN(taint_trim), &TAINT_O_FUNC(trim));
	php_taint_override_func(f_rtrim, PHP_FN(taint_rtrim), &TAINT_O_FUNC(rtrim));
	php_taint_override_func(f_ltrim, PHP_FN(taint_ltrim), &TAINT_O_FUNC(ltrim));
	php_taint_override_func(f_str_replace, PHP_FN(taint_str_replace), &TAINT_O_FUNC(str_replace));
	php_taint_override_func(f_str_ireplace, PHP_FN(taint_str_ireplace), &TAINT_O_FUNC(str_ireplace));
	php_taint_override_func(f_str_pad, PHP_FN(taint_str_pad), &TAINT_O_FUNC(str_pad));
	php_taint_override_func(f_strstr, PHP_FN(taint_strstr), &TAINT_O_FUNC(strstr));
	php_taint_override_func(f_strtolower, PHP_FN(taint_strtolower), &TAINT_O_FUNC(strtolower));
	php_taint_override_func(f_strtoupper, PHP_FN(taint_strtoupper), &TAINT_O_FUNC(strtoupper));
	php_taint_override_func(f_substr, PHP_FN(taint_substr), &TAINT_O_FUNC(substr));
	php_taint_override_func(f_dirname, PHP_FN(taint_dirname), &TAINT_O_FUNC(dirname));
	php_taint_override_func(f_basename, PHP_FN(taint_basename), &TAINT_O_FUNC(basename));
	php_taint_override_func(f_pathinfo, PHP_FN(taint_pathinfo), &TAINT_O_FUNC(pathinfo));
} /* }}} */

/* {{{ Frameless function interception (PHP 8.4+)
 *
 * Since PHP 8.4 the optimizer may emit ZEND_FRAMELESS_ICALL_* opcodes for a
 * handful of common functions (trim, implode, strstr, substr, str_replace,
 * dirname, ...). Those opcodes call zend_flf_handlers[] directly and bypass
 * func->internal_function.handler entirely, so the function handler swap
 * above is not sufficient. zend_flf_count is not an exported symbol, thus
 * the slots cannot be enumerated and swapped; instead the FRAMELESS_ICALL
 * opcodes themselves are hooked and re-executed here. */
#if PHP_VERSION_ID >= 80400

static int php_taint_flf_str_array_tainted(zval *arr) /* {{{ */ {
	zval *val;

	if (Z_TYPE_P(arr) != IS_ARRAY) {
		return 0;
	}
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), val) {
		ZVAL_DEREF(val);
		if (IS_STRING == Z_TYPE_P(val) && Z_STRLEN_P(val) && TAINT_POSSIBLE(Z_STR_P(val))) {
			return 1;
		}
	} ZEND_HASH_FOREACH_END();
	return 0;
} /* }}} */

/* Which frameless functions propagate taint, and how. Returns 0 when the
 * function is not handled by taint. */
static int php_taint_flic_check(zend_string *fname, int nargs, zval *arg1, zval *arg2, zval *arg3) /* {{{ */ {
	if (nargs >= 1 && zend_string_equals_literal(fname, "trim")) {
		return TAINT_STR_TAINTED(arg1);
	} else if (zend_string_equals_literal(fname, "implode")) {
		if (nargs == 1) {
			return php_taint_flf_str_array_tainted(arg1);
		} else if (nargs == 2) {
			/* arg1 is the separator, only the array elements are checked */
			return php_taint_flf_str_array_tainted(arg2);
		}
	} else if (nargs >= 2 && (zend_string_equals_literal(fname, "strstr")
			|| zend_string_equals_literal(fname, "substr"))) {
		return TAINT_STR_TAINTED(arg1);
	} else if (nargs == 3 && zend_string_equals_literal(fname, "str_replace")) {
		/* replace and subject propagate taint, search does not */
		return TAINT_STR_TAINTED(arg2) || TAINT_STR_TAINTED(arg3);
	} else if (nargs >= 1 && zend_string_equals_literal(fname, "dirname")) {
		return TAINT_STR_TAINTED(arg1);
	}
	return 0;
} /* }}} */

static int php_taint_flic_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zend_function *fbc;
	zval *result, *arg1 = NULL, *arg2 = NULL, *arg3 = NULL;
	taint_free_op free_op1 = NULL, free_op2 = NULL, free_op_data = NULL;
	int nargs, tainted = 0, handled;

	fbc = ZEND_FLF_FUNC(opline);
	nargs = opline->opcode - ZEND_FRAMELESS_ICALL_0;

	if (!fbc || fbc->type != ZEND_INTERNAL_FUNCTION || !fbc->common.function_name) {
		CALL_ORIGIN_HANDLER();
		return ZEND_USER_OPCODE_DISPATCH;
	}

	handled = 0;
	{
		zend_string *fname = fbc->common.function_name;
		if (zend_string_equals_literal(fname, "trim")
				|| zend_string_equals_literal(fname, "implode")
				|| zend_string_equals_literal(fname, "strstr")
				|| zend_string_equals_literal(fname, "substr")
				|| zend_string_equals_literal(fname, "str_replace")
				|| zend_string_equals_literal(fname, "dirname")) {
			handled = 1;
		}
	}

	/* defer to the engine when this function is not handled by taint or an
	 * observer (xdebug etc.) is watching it */
	if (!handled
			|| (ZEND_OBSERVER_ENABLED
				&& !zend_observer_handler_is_unobserved(ZEND_OBSERVER_DATA(fbc)))) {
		CALL_ORIGIN_HANDLER();
		return ZEND_USER_OPCODE_DISPATCH;
	}

	result = EX_VAR(opline->result.var);
	ZVAL_NULL(result);

	if (nargs >= 1) {
		arg1 = php_taint_get_zval_ptr(execute_data, opline, opline->op1_type, opline->op1, &free_op1, BP_VAR_R, 1);
		ZVAL_DEREF(arg1);
	}
	if (nargs >= 2) {
		arg2 = php_taint_get_zval_ptr(execute_data, opline, opline->op2_type, opline->op2, &free_op2, BP_VAR_R, 1);
		ZVAL_DEREF(arg2);
	}
	if (nargs >= 3) {
		arg3 = php_taint_get_zval_ptr(execute_data, opline + 1, (opline + 1)->op1_type, (opline + 1)->op1, &free_op_data, BP_VAR_R, 1);
		ZVAL_DEREF(arg3);
	}

	if (UNEXPECTED(EG(exception))) {
		if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
			zval_ptr_dtor_nogc(free_op1);
		}
		if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
			zval_ptr_dtor_nogc(free_op2);
		}
		if (((opline + 1)->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op_data) {
			zval_ptr_dtor_nogc(free_op_data);
		}
		ZVAL_UNDEF(result);
		return ZEND_HANDLE_EXCEPTION;
	}

	tainted = php_taint_flic_check(fbc->common.function_name, nargs, arg1, arg2, arg3);

	switch (nargs) {
		case 0:
			((zend_frameless_function_0)ZEND_FLF_HANDLER(opline))(result);
			break;
		case 1:
			((zend_frameless_function_1)ZEND_FLF_HANDLER(opline))(result, arg1);
			break;
		case 2:
			((zend_frameless_function_2)ZEND_FLF_HANDLER(opline))(result, arg1, arg2);
			break;
		default:
			((zend_frameless_function_3)ZEND_FLF_HANDLER(opline))(result, arg1, arg2, arg3);
			break;
	}

	if ((opline->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op1) {
		zval_ptr_dtor_nogc(free_op1);
		if (opline->op1_type & (IS_TMP_VAR|IS_VAR)) {
			ZVAL_UNDEF(EX_VAR(opline->op1.var));
		}
	}
	if ((opline->op2_type & (IS_TMP_VAR|IS_VAR)) && free_op2) {
		zval_ptr_dtor_nogc(free_op2);
		if (opline->op2_type & (IS_TMP_VAR|IS_VAR)) {
			ZVAL_UNDEF(EX_VAR(opline->op2.var));
		}
	}
	if (nargs >= 3 && (((opline + 1)->op1_type & (IS_TMP_VAR|IS_VAR)) && free_op_data)) {
		zval_ptr_dtor_nogc(free_op_data);
	}

	if (tainted && IS_STRING == Z_TYPE_P(result) && Z_STRLEN_P(result)) {
		TAINT_MARK(Z_STR_P(result));
	}

	if (UNEXPECTED(EG(exception))) {
		return ZEND_HANDLE_EXCEPTION;
	}
	execute_data->opline += (nargs >= 3) ? 2 : 1;
	return ZEND_USER_OPCODE_CONTINUE;
} /* }}} */

#endif /* PHP_VERSION_ID >= 80400 */

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

	if (Z_TYPE_P(num) == IS_STRING && TAINT_POSSIBLE(Z_STR_P(num))) {
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

	fprintf(stderr, "[taint_dbg] sprintf argc=%d tainted=%d\n", argc, tainted);
	TAINT_O_FUNC(sprintf)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	fprintf(stderr, "[taint_dbg] sprintf ret type=%d tainted=%d\n", Z_TYPE_P(return_value), tainted);
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
	int tainted = 0;

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
			ZVAL_DEREF(val);
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

/* {{{ proto string implode(string $separator[, array $args])
*/
PHP_FUNCTION(taint_implode) {
	zval *op1, *op2 = NULL;
	zval *target = NULL;
	int tainted = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_ZVAL(op1)
		Z_PARAM_OPTIONAL
		Z_PARAM_ZVAL(op2)
	ZEND_PARSE_PARAMETERS_END();

	if (op2 == NULL) {
		target = op1;
	} else {
		target = op2;
	}

	if (Z_TYPE_P(target) == IS_ARRAY) {
		zval *val;
		ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(target), val) {
			ZVAL_DEREF(val);
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
	zend_string *str, *what = NULL;
	int tainted = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(str)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(what)
	ZEND_PARSE_PARAMETERS_END();

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
	zend_string *str, *what = NULL;
	int tainted = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(str)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(what)
	ZEND_PARSE_PARAMETERS_END();

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(rtrim)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) &&
			Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string ltrim(string $str)
*/
PHP_FUNCTION(taint_ltrim)
{
	zend_string *str, *what = NULL;
	int tainted = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(str)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(what)
	ZEND_PARSE_PARAMETERS_END();

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(ltrim)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value) &&
			Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string str_replace(mixed $search, mixed $replace, mixed $subject [, int &$count])
*/
PHP_FUNCTION(taint_str_replace)
{
	zval *str, *from, *len = NULL, *repl;
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

/* {{{ proto string str_ireplace(mixed $search, mixed $replace, mixed $subject [, int &$count])
*/
PHP_FUNCTION(taint_str_ireplace)
{
	zval *str, *from, *len = NULL, *repl;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz|z", &str, &repl, &from, &len) == FAILURE) {
		return;
	}

	if (IS_STRING == Z_TYPE_P(repl) && TAINT_POSSIBLE(Z_STR_P(repl))) {
		tainted = 1;
	} else if (IS_STRING == Z_TYPE_P(from) && TAINT_POSSIBLE(Z_STR_P(from))) {
		tainted = 1;
	}

	TAINT_O_FUNC(str_ireplace)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

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
	bool part = 0;
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

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STR(str)
		Z_PARAM_LONG(f)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(l)
	ZEND_PARSE_PARAMETERS_END();

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

/* {{{ proto string dirname(string $path, int level)
*/
PHP_FUNCTION(taint_dirname) {
	zend_string *str;
	zend_long levels = 1;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|l", &str, &levels) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	TAINT_O_FUNC(dirname)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value)
			&& Z_STR_P(return_value) != str && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string basename(string $path[, string $suffix])
*/
PHP_FUNCTION(taint_basename) {
	zend_string *string, *suffix = NULL;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|S", &string, &suffix) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(string)) {
		tainted = 1;
	}

	TAINT_O_FUNC(basename)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted && IS_STRING == Z_TYPE_P(return_value)
			&& Z_STR_P(return_value) != string && Z_STRLEN_P(return_value)) {
		TAINT_MARK(Z_STR_P(return_value));
	}
}
/* }}} */

/* {{{ proto string pathinfo(string $path[, int $options])
*/
PHP_FUNCTION(taint_pathinfo) {
	zend_string *path;
	zend_long opt = 0;
	int tainted = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|l", &path, &opt) == FAILURE) {
		return;
	}

	if (TAINT_POSSIBLE(path)) {
		tainted = 1;
	}

	TAINT_O_FUNC(pathinfo)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (tainted) {
		if (IS_STRING == Z_TYPE_P(return_value)) {
			if (Z_STR_P(return_value) != path && Z_STRLEN_P(return_value)) {
				TAINT_MARK(Z_STR_P(return_value));
			}
		} else if (IS_ARRAY == Z_TYPE_P(return_value)) {
			php_taint_mark_strings(Z_ARRVAL_P(return_value));
		}
	}
}
/* }}} */

static PHP_INI_MH(OnUpdateErrorLevel) /* {{{ */ {
	if (!new_value) {
		TAINT_G(error_level) = E_USER_WARNING;
	} else {
		TAINT_G(error_level) = (int)atoi(ZSTR_VAL(new_value));
	}
	return SUCCESS;
} /* }}} */

/* {{{ PHP_INI
*/
PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("taint.enable", "0", PHP_INI_SYSTEM, OnUpdateBool, enable, zend_taint_globals, taint_globals)
	STD_PHP_INI_ENTRY("taint.error_level", "512", PHP_INI_ALL, OnUpdateErrorLevel, error_level, zend_taint_globals, taint_globals)
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
			/* string might be in shared memory */
			zend_string *str = zend_string_init(Z_STRVAL_P(el), Z_STRLEN_P(el), 0);
			zend_string_release(Z_STR_P(el));
			TAINT_MARK(str);
			ZVAL_STR(el, str);
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

	for (i = 0; i < argc; i++) {
		zval *el = &args[i];
		ZVAL_DEREF(el);
		if (IS_STRING == Z_TYPE_P(el) && TAINT_POSSIBLE(Z_STR_P(el))) {
			TAINT_CLEAN(Z_STR_P(el));
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

	ZVAL_DEREF(arg);
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
