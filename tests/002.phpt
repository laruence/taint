--TEST--
Check Taint function
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)

print $a;
$a .= '+';
$sql = "select * from {$a}";
file_put_contents("php://output", $a . "\n");
eval("return '$a';");
?>
--EXPECTF--
Warning: main() [print]: Attempt to print a string that might be tainted in %s002.php on line %d
tainted string.
Warning: main() [file_put_contents]: Attempt to output data that might be tainted in %s002.php on line %d
tainted string.+

Warning: main() [eval]: Code contains data that might be tainted in %s002.php on line %d
