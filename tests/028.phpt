--TEST--
Check sprintf/vsprintf propagation details
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

var_dump(is_tainted(sprintf("%s", $a)));
var_dump(is_tainted(sprintf("[%s]", $a)));
var_dump(is_tainted(sprintf("%d", $a)));           /* numeric output carries no original data */
var_dump(is_tainted(sprintf($a)));                 /* tainted format string */
var_dump(is_tainted(vsprintf("%s|%s", [$a, "clean" . chr(33)])));
var_dump(is_tainted(vsprintf("%s", ["clean" . chr(33)])));
var_dump(is_tainted(sprintf("%s", "clean" . chr(33))));

echo sprintf("output %s", $a), "\n";
?>
--EXPECTF--
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(false)
bool(false)

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s028.php on line %d
output tainted string.
