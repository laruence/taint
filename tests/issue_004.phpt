--TEST--
ISSUE #4 (wrong op fetched)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
function dummy(&$a) {
	extract(array("b" => "ccc"));
	$a = $b;
}

$c = "xxx". "xxx";
taint($c);
dummy($c);
var_dump($c);
?>
--EXPECTF--
string(3) "ccc"
