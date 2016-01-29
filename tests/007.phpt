--TEST--
Check Taint with functions
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

$b = sprintf("%s", $a);
var_dump(is_tainted($b));

$b = vsprintf("%s", array($a));
var_dump(is_tainted($b));

$b = explode(" ", $a);
var_dump(is_tainted($b[0]));

$a = implode(" ", $b);
var_dump(is_tainted($a));

$a = join(" ", $b);
var_dump(is_tainted($a));

$b = trim($a);
var_dump(is_tainted($a));
$b = rtrim($a, "a...Z");
var_dump(is_tainted($a));
$b = ltrim($a);
var_dump(is_tainted($a));

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
