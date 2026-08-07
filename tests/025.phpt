--TEST--
Check array propagation paths (append, dim assign, destructuring, foreach, copy)
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

$arr = [];
$arr[] = $a;
$arr["k"] = $a;
var_dump(is_tainted($arr[0]));
var_dump(is_tainted($arr["k"]));

[$x] = [$a];
list($y) = array($a);
var_dump(is_tainted($x));
var_dump(is_tainted($y));

foreach ($arr as $v) {
    var_dump(is_tainted($v));
}

$nested = ["l1" => ["l2" => $a]];
var_dump(is_tainted($nested["l1"]["l2"]));

$copy = $arr;
var_dump(is_tainted($copy["k"]));

$replaced = $arr;
$replaced["k"] = "clean" . chr(ord("!"));
var_dump(is_tainted($replaced["k"]));
var_dump(is_tainted($arr["k"]));
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
