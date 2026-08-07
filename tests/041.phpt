--TEST--
Header sinks: setcookie/setrawcookie name+value, mail() injection arguments
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
sendmail_path=/usr/bin/true
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

mail($a, "s", "b");
mail("to@example.com", $a, "b");
mail("to@example.com", "s", $a);            /* message body is not checked */
mail("to@example.com", "s", "b", $a);
mail("to@example.com", "s", "b", "h", $a);
echo "done\n";
?>
--EXPECTF--
Warning: main() [setcookie]: 2th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d

Warning: main() [setcookie]: 1th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d

Warning: main() [setrawcookie]: 2th argument contains data that might be tainted in %s041.php on line %d

Warning: Cannot modify header information - headers already sent by (output started at %s041.php:%d) in %s041.php on line %d

Warning: main() [mail]: 1th argument contains data that might be tainted in %s041.php on line %d

Warning: main() [mail]: 2th argument contains data that might be tainted in %s041.php on line %d

Warning: main() [mail]: 4th argument contains data that might be tainted in %s041.php on line %d

Warning: main() [mail]: 5th argument contains data that might be tainted in %s041.php on line %d
done
