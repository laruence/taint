--TEST--
taint.error_level controls the warning level at runtime
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

echo $a;
echo "\n";
ini_set("taint.error_level", 0);
echo $a;
echo "\nsuppressed\n";
ini_set("taint.error_level", 512); /* E_USER_WARNING */
echo $a;
echo "\n";
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s037.php on line %d
tainted string.
tainted string.
suppressed

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s037.php on line %d
tainted string.
