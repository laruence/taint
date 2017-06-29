--TEST--
Bug #63123 (Hash pointer should be reset at the end of function:php_taint_mark_strings)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 

$str = 'a,' . 'b';
taint($str);
$a = explode(',', $str);
while (list($key, $val) = @each($a)) {
    echo $val;
}

?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %sbug63123.php on line %d
a
Warning: main() [echo]: Attempt to echo a string that might be tainted in %Sbug63123.php on line %d
b
