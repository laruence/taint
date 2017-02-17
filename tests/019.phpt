--TEST--
Non existent array key cannot be tainted
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
$a = array();
taint($a['noneExistent']);
var_dump(is_tainted($a['noneExistent']));
--EXPECTF--
bool(true)
