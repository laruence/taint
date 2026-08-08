--TEST--
mail() injection arguments are checked, message body is not
--SKIPIF--
<?php
if (!extension_loaded("taint")) print "skip";
if (strncasecmp(PHP_OS, "WIN", 3) == 0) print "skip needs unix sendmail_path";
?>
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

mail($a, "s", "b");
mail("to@example.com", $a, "b");
mail("to@example.com", "s", $a);            /* message body is not checked */
mail("to@example.com", "s", "b", $a);
mail("to@example.com", "s", "b", "h", $a);
echo "done\n";
?>
--EXPECTF--
Warning: main() [mail]: 1th argument contains data that might be tainted in %s046.php on line %d

Warning: main() [mail]: 2th argument contains data that might be tainted in %s046.php on line %d

Warning: main() [mail]: 4th argument contains data that might be tainted in %s046.php on line %d

Warning: main() [mail]: 5th argument contains data that might be tainted in %s046.php on line %d
done
