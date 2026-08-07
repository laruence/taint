--TEST--
Bug #63123 (Hash pointer should be reset at the end of function:php_taint_mark_strings)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php

$x = 'bb';
$str = 'aa,' . $x;
taint($str);
$a = explode(',', $str);
foreach ($a as $key => $val) {
    echo $val;
}

?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %sbug63123.php on line %d
aa
Warning: main() [echo]: Attempt to echo a string that might be tainted in %sbug63123.php on line %d
bb
