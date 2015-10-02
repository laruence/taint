--TEST--
Check preg_replace_callback
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
function test() {
}

$fname = "tes" . chr(ord("t"));
taint($fname);

preg_replace_callback("/xxxx/", $fname, "xxxx");
?>
--EXPECTF--
Warning: main() [preg_replace_callback]: Callback name contains data that might be tainted in %s015.php on line 8
