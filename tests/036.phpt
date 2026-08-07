--TEST--
Assign-op concat edges: undefined CV, scalars, append, new properties, string offsets
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
error_reporting(E_ALL);
$a = "tainted string" . ".";
taint($a);

unset($u);
$u .= $a;
var_dump(is_tainted($u));

$n = 1;
$n .= $a;
var_dump(is_tainted($n));

$arr = array();
$arr[] .= $a;
var_dump(is_tainted($arr[0]));

$std = new stdClass();
$std->newprop .= $a;
var_dump(is_tainted($std->newprop));

$clean = "x";
$clean .= "y";
var_dump(is_tainted($clean));

try {
    $s = "abc";
    $s[0] .= $a;
} catch (Error $e) {
    echo "caught: ", $e->getMessage(), "\n";
}
?>
--EXPECTF--
Warning: Undefined variable $u in %s036.php on line %d
bool(true)
bool(true)
bool(true)

Warning: Undefined property: stdClass::$newprop in %s036.php on line %d
bool(true)
bool(false)
caught: Cannot use assign-op operators with string offsets
