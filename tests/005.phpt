--TEST--
Check Taint with separation 
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

$b = $a;
$c = &$b; //separation
echo $b;
print $c;

$e = $a; //separation
echo $e;
print $a;
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s005.php on line %d
tainted string.
Warning: main() [print]: Attempt to print a string that might be tainted in %s005.php on line %d
tainted string.
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s005.php on line %d
tainted string.
Warning: main() [print]: Attempt to print a string that might be tainted in %s005.php on line %d
tainted string.
