--TEST--
Bug #63100 (array_walk_recursive behaves wrongly when taint enabled)
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php 
$a = array();
$a[0] = "tainted string" . "<>";
taint($a[0]);

function xxx(&$item) {
    $item = htmlspecialchars($item);
}

array_walk_recursive($a, "xxx");

echo $a[0];

?>
--EXPECTF--
tainted string&lt;&gt;
