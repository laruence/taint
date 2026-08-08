--TEST--
Header sinks: setcookie/setrawcookie name+value
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$a = "tainted string" . ".";
taint($a);
$cn = "na" . "me";
taint($cn);
$cv = "tainted" . "value";
taint($cv);

/* negative first: no output yet, so no headers-sent noise */
setcookie("session", "clean");

setcookie("session", $a);
setcookie($cn, "value");
setrawcookie("session", $cv);

echo "done\n";
?>
--EXPECTF--
Warning: main() [setcookie]: 2th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d

Warning: main() [setcookie]: 1th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d

Warning: main() [setrawcookie]: 2th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d
done
