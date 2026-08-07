--TEST--
Check rope (string interpolation) propagation
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
$b = "another one" . "!";
taint($b);

var_dump(is_tainted("x {$a} y"));                 // single var in rope
var_dump(is_tainted("pre $a post"));              // simple var interpolation
var_dump(is_tainted("{$a} and {$b}"));            // multi node rope
var_dump(is_tainted("num: " . 1 . " str: {$a}")); // mixed const/tmp/cv
var_dump(is_tainted(<<<DOC
heredoc with {$a} inside
DOC));
var_dump(is_tainted("nothing to see here"));      // clean rope-less literal
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
