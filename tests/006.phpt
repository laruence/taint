--TEST--
Check Taint with send_var/send_ref
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

function test1(&$a) {
   echo $a;
}

function test2($b) {
   echo $b;
}

test1($a);
test2($a);
$b = $a;

test1($a);
test2($a);

$c = "tainted string" . ".";
taint($c);

$e = &$c;

test1($c);
test2($c);

?>
--EXPECTF--
Warning: test1() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 6
tainted string.
Warning: test2() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 10
tainted string.
Warning: test1() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 6
tainted string.
Warning: test2() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 10
tainted string.
Warning: test1() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 6
tainted string.
Warning: test2() [echo]: Attempt to echo a string that might be tainted in %s006.php on line 10
tainted string.
