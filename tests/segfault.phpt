--TEST--
Segfault when re-taint a string which lost its taint flag
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)
var_dump(is_tainted($a));

$a = preg_replace('{^\s*SELECT}i', 'SELECT/*', $a, 1);
var_dump(is_tainted($a));

taint($a);
var_dump(is_tainted($a));

?>
--EXPECTF--
bool(true)
bool(false)
bool(true)
