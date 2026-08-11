--TEST--
File sinks: file_put_contents/copy/rename/mkdir/rmdir/touch/move_uploaded_file paths
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

$dir = "/nonexistent_dir/" . $a;
file_put_contents($dir, "data");
mkdir($dir);
touch($dir);
copy($a, "/nonexistent_dir/x");
rename($a, "/nonexistent_dir/x");
move_uploaded_file($a, "/nonexistent_dir/x");
rmdir($a);

/* tainted destination paths */
$src = sys_get_temp_dir() . "/taint043src";
file_put_contents($src, "clean");
copy($src, $dir);
rename($src, $dir);

/* negative: clean paths must not warn */
$base = sys_get_temp_dir() . "/taint043dir";
mkdir($base);
file_put_contents($base . "/f", "x");
unlink($base . "/f");
rmdir($base);
unlink($src);
echo "done\n";
?>
--EXPECTF--
Warning: main() [file_put_contents]: Attempt to write a file which path might be tainted in %s043.php on line %d

Warning: file_put_contents(%s: Failed to open stream: %s in %s043.php on line %d

Warning: main() [mkdir]: Path contains data that might be tainted in %s043.php on line %d

Warning: mkdir(): %s in %s043.php on line %d

Warning: main() [touch]: Path contains data that might be tainted in %s043.php on line %d

Warning: touch(): %s in %s043.php on line %d

Warning: main() [copy]: Source path contains data that might be tainted in %s043.php on line %d

Warning: copy(%s: Failed to open stream: %s in %s043.php on line %d

Warning: main() [rename]: Source path contains data that might be tainted in %s043.php on line %d

Warning: rename(%s: %s in %s043.php on line %d

Warning: main() [move_uploaded_file]: Source path contains data that might be tainted in %s043.php on line %d

Warning: main() [rmdir]: Path contains data that might be tainted in %s043.php on line %d

Warning: rmdir(%s: %s in %s043.php on line %d

Warning: main() [copy]: Destination path contains data that might be tainted in %s043.php on line %d

Warning: copy(%s: %s in %s043.php on line %d

Warning: main() [rename]: Destination path contains data that might be tainted in %s043.php on line %d

Warning: rename(%s: %s in %s043.php on line %d
done
