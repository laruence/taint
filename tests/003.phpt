--TEST--
Check Taint with ternary
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

$b = isset($a)? $a : 0;
echo $b;

$b .= isset($a)? "xxxx" : 0; //a knew mem leak
exit($b);
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s003.php on line %d
tainted string.
Warning: main() [exit]: Attempt to output a string that might be tainted in %s003.php on line %d
tainted string.xxxx
