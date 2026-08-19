--TEST--
Check propagation through propagator functions at every registered arity (frameless and wrapper paths)
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

/* trim family: trim is frameless (arity 1,2), ltrim/rtrim go through wrappers */
var_dump(is_tainted(trim($a)));
var_dump(is_tainted(trim($a, "g.")));
var_dump(is_tainted(ltrim($a, "t")));
var_dump(is_tainted(rtrim($a, ".")));

/* substr: frameless arity 2 and 3 */
var_dump(is_tainted(substr($a, 2)));
var_dump(is_tainted(substr($a, 2, 4)));

/* strstr: frameless arity 2 and 3 (before_needle) */
var_dump(is_tainted(strstr($a, "string")));
var_dump(is_tainted(strstr($a, "string", true)));

/* implode: frameless arity 1 and 2 */
var_dump(is_tainted(implode([$a])));
var_dump(is_tainted(implode(",", [$a, "clean" . chr(33)])));
/* a tainted separator flows into the result too; clean input stays clean */
var_dump(is_tainted(implode($a, ["clean", "strings"])));
var_dump(is_tainted(implode(",", ["clean", "strings"])));

/* str_replace: frameless arity 3 */
var_dump(is_tainted(str_replace("string", "rope", $a)));

/* dirname: frameless arity 1 and 2 */
var_dump(is_tainted(dirname("/tmp/" . $a)));
var_dump(is_tainted(dirname("/tmp/" . $a, 1)));

/* not frameless, wrapper path */
var_dump(is_tainted(strval($a)));
var_dump(is_tainted(basename("/tmp/" . $a)));
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
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
