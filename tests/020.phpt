--TEST--
preg_replace() untaints a string
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
$query = "SELECT * FROM ..".".";
taint($query); //must use concat to make the string not a internal string(introduced in 5.4)
var_dump(is_tainted($query));

$query = preg_replace('{^\s*SELECT}i', 'SELECT/*', $query, 1);
var_dump(is_tainted($query));
--EXPECTF--
bool(true)
bool(true)
