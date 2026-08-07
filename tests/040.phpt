--TEST--
Output sinks: var_dump, var_export, printf format string, vprintf format string
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

var_dump($a);
var_dump("clean", $a);
var_export($a);
echo "\n";
printf($a);
echo "\n";
vprintf($a, array());
echo "\n";

/* negative: none of these may warn for clean data */
var_dump("only clean");
var_export("only clean", true);
printf("clean fmt\n");
vprintf("clean %s\n", array("v"));
?>
--EXPECTF--
Warning: main() [var_dump]: Attempt to var_dump data that might be tainted in %s040.php on line %d
string(15) "tainted string."

Warning: main() [var_dump]: Attempt to var_dump data that might be tainted in %s040.php on line %d
string(5) "clean"
string(15) "tainted string."

Warning: main() [var_export]: Attempt to var_export data that might be tainted in %s040.php on line %d
'tainted string.'

Warning: main() [printf]: 1th argument contains data that might be tainted in %s040.php on line %d
tainted string.

Warning: main() [vprintf]: 1th argument contains data that might be tainted in %s040.php on line %d
tainted string.
string(10) "only clean"
clean fmt
clean v
