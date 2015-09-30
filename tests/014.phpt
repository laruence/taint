--TEST--
Check function call
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

$fname();

call_user_func($fname);

call_user_func_array($fname, array());

?>
--EXPECTF--
Warning: main() [fcall]: Attempt to call a function which name might be tainted in %s014.php on line 8

Warning: main() [fcall]: Attempt to call a function which name might be tainted in %s014.php on line 10

Warning: main() [fcall]: Attempt to call a function which name might be tainted in %s014.php on line 12
