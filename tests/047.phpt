--TEST--
Check preg_* patterns
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$p = "/x" . chr(ord("x")) . "/";
taint($p);

preg_match($p, "xxx");
preg_match_all($p, "xxx");
preg_replace($p, "y", "xxx");
preg_split($p, "xxx");
preg_grep($p, ["a", "b"]);
preg_replace_callback($p, function($m) { return $m[0]; }, "xxx");
preg_match("/xxx/", "xxx"); /* clean pattern, must not warn */
echo "done\n";
?>
--EXPECTF--
Warning: main() [preg_match]: Pattern contains data that might be tainted in %s047.php on line %d

Warning: main() [preg_match_all]: Pattern contains data that might be tainted in %s047.php on line %d

Warning: main() [preg_replace]: Pattern contains data that might be tainted in %s047.php on line %d

Warning: main() [preg_split]: Pattern contains data that might be tainted in %s047.php on line %d

Warning: main() [preg_grep]: Pattern contains data that might be tainted in %s047.php on line %d

Warning: main() [preg_replace_callback]: Pattern contains data that might be tainted in %s047.php on line %d
done
