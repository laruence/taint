--TEST--
Sinks outside the check list stay silent even for tainted data
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

print_r(array("k" => $a));
echo "\n";
var_dump($a);
printf("no-args format\n");
?>
--EXPECTF--
Array
(
    [k] => tainted string.
)

string(15) "tainted string."
no-args format
