--TEST--
Check header
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$str = "Location: " . str_repeat("xx", 2);

taint($str);

header($str);
?>
--EXPECTF--
Warning: main() [header]: Attempt to send a header that might be tainted in %s016.php on line 6

%s
