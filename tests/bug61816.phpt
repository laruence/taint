--TEST--
Bug #61816 (Segmentation fault)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
$a = "tainted string" . ".\n";
taint($a);
$b = array("");
$b[0] .= $a;
var_dump(is_tainted($b[0]));
$c = new stdClass();
$c->foo = "this is";
$c->foo .= $b[0];
echo $b[0];  // Segmentation fault
var_dump(is_tainted($c->foo));
?>
--EXPECTF--
bool(true)

Warning: main() [echo]: Attempt to echo a string that might be tainted in %sbug61816.php on line %d
tainted string.
bool(true)
