--TEST--
Check unerialize
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
$str = serialize(array());

taint($str);

unserialize($str);
?>
--EXPECTF--
Warning: main() [unserialize]: Attempt to unserialize a string that might be tainted in %s017.php on line 6
