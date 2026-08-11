--TEST--
include / include_once warnings for tainted paths, clean path stays silent
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
$f = "/nonexistent_" . $a;
include($f);
include_once($f);
$clean = "/nonexistent_clean_file_xyz";
include($clean);
echo "done\n";
?>
--EXPECTF--
Warning: main() [include]: File path contains data that might be tainted in %s030.php on line %d

Warning: include(%s: Failed to open stream: %s in %s030.php on line %d

Warning: include(): Failed opening '%s' for inclusion (include_path='%s') in %s030.php on line %d

Warning: main() [include_once]: File path contains data that might be tainted in %s030.php on line %d

Warning: include_once(%s: Failed to open stream: %s in %s030.php on line %d

Warning: include_once(): Failed opening '%s' for inclusion (include_path='%s') in %s030.php on line %d

Warning: include(%s: Failed to open stream: %s in %s030.php on line %d

Warning: include(): Failed opening '%s' for inclusion (include_path='%s') in %s030.php on line %d
done
