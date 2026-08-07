--TEST--
Code display sinks: highlight_file / show_source with tainted and clean paths
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

/* negative: clean path only produces engine warnings */
highlight_file("/nonexistent_clean_path");

highlight_file($a);
show_source($a);
echo "done\n";
?>
--EXPECTF--
Warning: highlight_file(%s): Failed to open stream: %s in %s044.php on line %d

Warning: highlight_file(): Failed opening %s for highlighting in %s044.php on line %d

Warning: main() [highlight_file]: Attempt to read a file which path might be tainted in %s044.php on line %d

Warning: highlight_file(%s): Failed to open stream: %s in %s044.php on line %d

Warning: highlight_file(): Failed opening %s for highlighting in %s044.php on line %d

Warning: main() [show_source]: Attempt to read a file which path might be tainted in %s044.php on line %d

Warning: show_source(%s): Failed to open stream: %s in %s044.php on line %d

Warning: show_source(): Failed opening %s for highlighting in %s044.php on line %d
done
