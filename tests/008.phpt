--TEST--
Check Taint with more functions
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

$b = strstr($a, "s");
var_dump(is_tainted($b));

$b = substr($a, 0, 4);
var_dump(is_tainted($b));

$b = str_replace("str,", "btr", $a);
var_dump(is_tainted($b));

$b = str_ireplace("str,", "btr", $a);
var_dump(is_tainted($b));

$b = str_pad($a, 32);
var_dump(is_tainted($b));

$b = str_pad("test", 32, $a);
var_dump(is_tainted($b));

$b = strtolower($a);
var_dump(is_tainted($b));

$b = strtoupper($a);
var_dump(is_tainted($b));
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
