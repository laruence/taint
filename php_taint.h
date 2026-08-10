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

#ifndef PHP_TAINT_H
#define PHP_TAINT_H

#if PHP_VERSION_ID < 80000
# error "taint 3.x requires PHP 8.0+, use taint 2.1.x for PHP 7.x"
#endif

extern zend_module_entry taint_module_entry;
#define phpext_taint_ptr &taint_module_entry

#ifdef PHP_WIN32
#define PHP_TAINT_API __declspec(dllexport)
#else
#define PHP_TAINT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define PHP_TAINT_VERSION "3.0.1-dev"

/* Since PHP 7.3 every bit in the GC_FLAGS region of a zend_string is
 * already taken (IS_STR_CLASS_NAME_MAP_PTR/IS_STR_INTERNED/IS_STR_PERSISTENT
 * /IS_STR_PERMANENT/IS_STR_VALID_UTF8, bits 5..9), so the taint marker has
 * to live in the GC_INFO region instead. Strings never participate in the
 * cycle GC (no gc roots, no colors), therefore GC_INFO bit 0 (bit 10 of
 * type_info) is guaranteed to be free for strings. */
#define IS_STR_TAINT_POSSIBLE    (1u << GC_INFO_SHIFT)

/* Interned strings may be shared across requests (opcache SHM), persistent /
 * permanent strings live beyond a single request: never mark those. Bit 6 =
 * IS_STR_INTERNED (GC_IMMUTABLE), bit 7 = IS_STR_PERSISTENT (GC_PERSISTENT),
 * bit 8 = IS_STR_PERMANENT (GC_PERSISTENT_LOCAL). */
#define TAINT_MARK(str) do { \
		zend_string *_s = (str); \
		if (!(_s->gc.u.type_info & (GC_IMMUTABLE | GC_PERSISTENT | GC_PERSISTENT_LOCAL))) { \
			_s->gc.u.type_info |= IS_STR_TAINT_POSSIBLE; \
		} \
	} while (0)
/* GC_FLAGS()/GC_INFO() mask the type_info, test/clean the raw word instead */
#define TAINT_POSSIBLE(str) ((str)->gc.u.type_info & IS_STR_TAINT_POSSIBLE)
#define TAINT_CLEAN(str)    ((str)->gc.u.type_info &= ~IS_STR_TAINT_POSSIBLE)

#define EX_CONSTANT(op) RT_CONSTANT(EX(opline), op)

#define TAINT_OP1_TYPE(opline)	(opline->op1_type)
#define TAINT_OP2_TYPE(opline)	(opline->op2_type)

#define TAINT_RET_USED(opline) ((opline)->result_type != IS_UNUSED)
#define TAINT_ISERR(var)       (Z_ISERROR_P(var))
#define TAINT_ERR_ZVAL(var)    (ZVAL_ERROR(var))

typedef zval* taint_free_op;

PHP_MINIT_FUNCTION(taint);
PHP_MSHUTDOWN_FUNCTION(taint);
PHP_RINIT_FUNCTION(taint);
PHP_RSHUTDOWN_FUNCTION(taint);
PHP_MINFO_FUNCTION(taint);

PHP_FUNCTION(taint);
PHP_FUNCTION(untaint);
PHP_FUNCTION(is_tainted);

PHP_FUNCTION(taint_strval);
PHP_FUNCTION(taint_sprintf);
PHP_FUNCTION(taint_vsprintf);
PHP_FUNCTION(taint_explode);
PHP_FUNCTION(taint_implode);
PHP_FUNCTION(taint_trim);
PHP_FUNCTION(taint_rtrim);
PHP_FUNCTION(taint_ltrim);
PHP_FUNCTION(taint_strstr);
PHP_FUNCTION(taint_substr);
PHP_FUNCTION(taint_str_replace);
PHP_FUNCTION(taint_str_ireplace);
PHP_FUNCTION(taint_str_pad);
PHP_FUNCTION(taint_strtolower);
PHP_FUNCTION(taint_strtoupper);
PHP_FUNCTION(taint_dirname);
PHP_FUNCTION(taint_basename);
PHP_FUNCTION(taint_pathinfo);

typedef zif_handler php_func;

ZEND_BEGIN_MODULE_GLOBALS(taint)
	bool enable;
	int  error_level;
ZEND_END_MODULE_GLOBALS(taint)

#ifdef ZTS
#define TAINT_G(v) TSRMG(taint_globals_id, zend_taint_globals *, v)
#else
#define TAINT_G(v) (taint_globals.v)
#endif

#endif	/* PHP_TAINT_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
