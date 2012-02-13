dnl $Id$

PHP_ARG_ENABLE(taint, whether to enable taint support,
[  --enable-taint           Enable taint support])

if test "$PHP_TAINT" != "no"; then
  PHP_NEW_EXTENSION(taint, taint.c, $ext_shared)
fi
