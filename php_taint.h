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

/* $Id: header 297205 2010-03-30 21:09:07Z johannes $ */

#ifndef PHP_TAINT_H
#define PHP_TAINT_H

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

#define PHP_TAINT_VERSION "0.1"

#define PHP_TAINT_MAGIC_LENGTH   sizeof(unsigned)
#define PHP_TAINT_MAGIC_NONE     0x00000000
#define PHP_TAINT_MAGIC_POSSIBLE 0x6A8FCE84
#define PHP_TAINT_MAGIC_UNTAINT  0x2C5E7F2D

#define TAINT_T(offset) (*(temp_variable *)((char *) execute_data->Ts + offset))
#define TAINT_TS(offset) (*(temp_variable *)((char *)Ts + offset))
#define TAINT_CV(i)     (EG(current_execute_data)->CVs[i])
#define TAINT_PZVAL_LOCK(z) Z_ADDREF_P(z);
#define TAINT_PZVAL_UNLOCK(z, f) taint_pzval_unlock_func(z, f, 1)
#define TAINT_PZVAL_UNLOCK_FREE(z) taint_pzval_unlock_free_func(z)
#define TAINT_CV_OF(i)     (EG(current_execute_data)->CVs[i])
#define TAINT_CV_DEF_OF(i) (EG(active_op_array)->vars[i])
#define TAINT_AI_USE_PTR(ai) \
	if ((ai).ptr_ptr) { \
		(ai).ptr = *((ai).ptr_ptr); \
		(ai).ptr_ptr = &((ai).ptr); \
	} else { \
		(ai).ptr = NULL; \
	}

#define PHP_TAINT_MARK(zv, mark) *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) = (mark)
#define PHP_TAINT_POSSIBLE(zv) (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_POSSIBLE)
#define PHP_TAINT_UNTAINT(zv)  (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_UNTAINT)

#if ((PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3))
#  define Z_ADDREF_P   ZVAL_ADDREF
#  define Z_REFCOUNT_P ZVAL_REFCOUNT
#  define Z_DELREF_P   ZVAL_DELREF
#  define Z_SET_REFCOUNT_P(pz, rc)  (pz)->refcount = rc 
#  define Z_UNSET_ISREF_P(pz) (pz)->is_ref = 0 
#  define Z_ISREF_P(pz)       (pz)->is_ref
#endif

PHP_MINIT_FUNCTION(taint);
PHP_MSHUTDOWN_FUNCTION(taint);
PHP_RINIT_FUNCTION(taint);
PHP_RSHUTDOWN_FUNCTION(taint);
PHP_MINFO_FUNCTION(taint);

PHP_FUNCTION(untaint);
PHP_FUNCTION(is_tainted);

ZEND_BEGIN_MODULE_GLOBALS(taint)
	zend_bool enable;
	int       error_level;
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
