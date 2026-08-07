--TEST--
Check concat/concat_fast propagation with different operand types
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
$clean = "clean" . chr(ord("!"));

var_dump(is_tainted("pre " . $a));          // CONST . CV
var_dump(is_tainted($a . " post"));         // CV . CONST
var_dump(is_tainted($a . $clean));          // CV . CV, taint wins
var_dump(is_tainted($clean . $a));          // CV . CV, taint wins
var_dump(is_tainted($a . $a));              // CV . CV same var
var_dump(is_tainted("clean" . chr(33) . $a)); // TMPVAR chain . CV
var_dump(is_tainted($a . strtoupper($a)));  // CV . TMPVAR
var_dump(is_tainted("clean" . chr(ord("!")))); // clean only
var_dump(is_tainted($clean));
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(false)
