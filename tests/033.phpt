--TEST--
References and shared strings: the taint bit lives on the zend_string
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

$ref = &$a;
echo $ref;
echo "\n";

$copy = $a;
untaint($a);
var_dump(is_tainted($copy));

$b = "tainted again" . "!";
taint($b);
$ref2 = &$b;
untaint($ref2);
var_dump(is_tainted($b));
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s033.php on line %d
tainted string.
bool(false)
bool(false)
