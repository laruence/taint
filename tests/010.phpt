--TEST--
Check Taint with dim assign contact
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a);
$b = array("this is");
$b[0] .= $a;
var_dump(is_tainted($b)); //@FIXME

$c = new stdClass();
$c->foo = "this is";
$c->foo .= $a;

var_dump(is_tainted($c));
?>
--EXPECTF--
Warning: main(): Right operand of assign concat(.=) is a tainted string in %s010.php on line %d
bool(false)

Warning: main(): Right operand of assign concat(.=) is a tainted string in %s010.php on line %d
bool(false)
