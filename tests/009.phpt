--TEST--
Fixed bug that tainted info lost if a string is parsed by htmlspecialchars
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

$b = htmlspecialchars($a);
var_dump(is_tainted($b));
var_dump(is_tainted($a));
?>
--EXPECTF--
bool(false)
bool(true)
