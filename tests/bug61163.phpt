--TEST--
Bug #61163 (Passing and using tainted data in specific way crashes)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$b = ".";
$a = "tainted string" . $b; // literals get constant-folded to interned strings, which taint() refuses to mark
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)
function test($test)
{
	$data .= $test; // $data doesn't exist yet.
}

test($a);
--EXPECTF--
Warning: Undefined variable $data in %sbug61163.php on line %d
