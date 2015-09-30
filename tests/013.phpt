--TEST--
Check file, file_get_contents
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
function test() {
	$a = __FILE__ . chr(ord("t"));
	taint($a);
    $str = file($a);
	$str = file_get_contents($a);
}

test();
?>
--EXPECTF--
Warning: test() [file]: Attempt to read a file which path might be tainted in %s013.php on line 5

Warning: test() [file_get_contents]: Attempt to read a file which path might be tainted in %s013.php on line 6
