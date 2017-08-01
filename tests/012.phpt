--TEST--
Check dirname, basename, pathinfo
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
function test() {
	$a = __FILE__ . chr(ord("/"));
	taint($a);
    echo dirname($a);
	echo basename($a);
	echo pathinfo($a, PATHINFO_BASENAME);
	echo pathinfo($a)["dirname"];
}

test();
?>
--EXPECTF--
Warning: test() [echo]: Attempt to echo a string that might be tainted in %s012.php on line 5
%s
Warning: test() [echo]: Attempt to echo a string that might be tainted in %s012.php on line 6
012.php
Warning: test() [echo]: Attempt to echo a string that might be tainted in %s012.php on line 7
012.php
Warning: test() [echo]: Attempt to echo a string that might be tainted in %s012.php on line 8
%s
