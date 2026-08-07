--TEST--
Check echo with multiple arguments and print as expression
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$a = "tainted string" . ".";
taint($a);
$b = "another one" . "!";
taint($b);

echo $a, " mid ", $b, "\n";

$ret = print $a;
var_dump($ret);
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s026.php on line %d
tainted string. mid 
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s026.php on line %d
another one!

Warning: main() [print]: Attempt to print a string that might be tainted in %s026.php on line %d
tainted string.int(1)
