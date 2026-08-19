--TEST--
Check taint does NOT propagate from non-propagating arguments (false positive guard)
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
$needle = "llo";
taint($needle);

/* only search tainted: replacement result must stay clean */
var_dump(is_tainted(str_replace($a, "x", "haystack")));
var_dump(is_tainted(str_ireplace($a, "x", "haystack")));

/* only needle tainted: result is a substring of the clean haystack */
var_dump(is_tainted(strstr("hello world", $needle)));

/* only charlist tainted */
var_dump(is_tainted(trim("  hello  ", $a)));
var_dump(is_tainted(ltrim("hello", $a)));
var_dump(is_tainted(rtrim("hello", $a)));

/* only suffix tainted */
var_dump(is_tainted(basename("/tmp/file.txt", $a)));

/* functions outside the propagator whitelist never propagate */
var_dump(is_tainted(md5($a)));
var_dump(is_tainted(strrev($a)));
var_dump(is_tainted(urlencode($a)));
var_dump(is_tainted(htmlspecialchars($a)));

/* numeric conversion drops taint */
var_dump(is_tainted((string)(int)$a));
var_dump(is_tainted(strval((int)$a)));
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
