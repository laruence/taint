--TEST--
Bug #61163 (Passing and using tainted data in specific way crashes)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
$a = "tainted string" . ".";
taint($a); //must use concat to make the string not a internal string(introduced in 5.4)
function test($test)
{
	$data .= $test; // $data doesn't exist yet.
}

test($a);
--EXPECTF--
Notice: Undefined variable: data in %sbug61163.php on line %d
