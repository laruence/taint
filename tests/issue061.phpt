--TEST--
ISSUE #061 (PHP 7.2.6 SIGSEGV)
--SKIPIF--
<?php
if (!extension_loaded('taint') || !extension_loaded('pdo_sqlite')) print 'skip not loaded';
?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
var_dump(substr('abc', 0, 2));
var_dump(trim('abc', 'c'));
var_dump(rtrim('abc', 'c'));
var_dump(ltrim('abc', 'c'));
var_dump(implode('b', array('a', 'c')));
?>
--EXPECT--
string(2) "ab"
string(2) "ab"
string(2) "ab"
string(3) "abc"
string(3) "abc"
