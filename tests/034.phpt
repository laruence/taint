--TEST--
Marking limits: interned results cannot be marked, taint() copies when needed
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$a = "tainted string" . ".";
taint($a);

var_dump(is_tainted(substr($a, 0, 1)));   /* single-char result is interned */
var_dump(is_tainted(substr($a, 100)));     /* empty result */

$lit = "ab" . "cd";
var_dump(is_tainted($lit));                /* constant-folded literal */
taint($lit);
var_dump(is_tainted($lit));                /* taint() copies, copy is markable */

$one = "x";
taint($one);
var_dump(is_tainted($one));                /* single chars are interned too */
?>
--EXPECT--
bool(false)
bool(false)
bool(false)
bool(true)
bool(true)
