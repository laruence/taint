--TEST--
Check propagation chain and untaint breaking the chain
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

$b = trim($a);
$c = "select " . $b;
$d = strtoupper($c);
echo $d, "\n";

untaint($d);
$e = $d . " from db";
echo $e, "\n";
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s023.php on line %d
SELECT TAINTED STRING.
SELECT TAINTED STRING. from db
