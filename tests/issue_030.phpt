--TEST--
ISSUE #30 (call_user_func)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
report_memleaks=0
--FILE--
<?php
$a = "tainted string" . ".";
taint($a);
$b = call_user_func('test', $a);

function test($a) {
  return $a;
}

echo $b;
?>
--EXPECTF--
Warning: main(): Attempt to echo a string that might be tainted in %sissue_030.php on line %d
tainted string.
