--TEST--
taint/untaint/is_tainted semantics on non-strings, empty strings and literals
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
var_dump(is_tainted(123));
var_dump(is_tainted(1.5));
var_dump(is_tainted(array()));
var_dump(is_tainted(null));
var_dump(is_tainted(true));
var_dump(is_tainted(new stdClass()));
var_dump(is_tainted(""));

$i = 123;
var_dump(taint($i));
var_dump(is_tainted($i));

$e = "";
var_dump(taint($e));
var_dump(is_tainted($e));

$a = "multi one" . "!";
$b = "multi two" . "?";
taint($a, $b);
var_dump(is_tainted($a), is_tainted($b));

try {
    taint("literal");
} catch (Error $err) {
    echo "caught: ", $err->getMessage(), "\n";
}

$c = "clean" . "ed";
var_dump(untaint($c));
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(true)
caught: taint(): Argument #1 ($string) c%st be passed by reference
bool(true)
