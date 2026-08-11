--TEST--
Sink warnings: printf, vprintf, print_r, fopen, unlink, readfile, opendir
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

printf("p:%s\n", $a);
vprintf("v:%s\n", array($a));
vprintf("%s%s\n", array("k" => "clean", "x" => $a));
print_r($a); echo "\n";

$p = "/nonexistent_dir/" . $a;
fopen($p, "r");
unlink($p);
readfile($p);
opendir($p);
?>
--EXPECTF--
Warning: main() %s that might be tainted in %s029.php on line %d
p:tainted string.

Warning: main() [vprintf]: Second argument contains data(index:0) that might be tainted in %s029.php on line %d
v:tainted string.

Warning: main() [vprintf]: Second argument contains data(index:x) that might be tainted in %s029.php on line %d
cleantainted string.

Warning: main() [print_r]: Attempt to print_r data that might be tainted in %s029.php on line %d
tainted string.

Warning: main() [fopen]: Attempt to open a file which path might be tainted in %s029.php on line %d

Warning: fopen(%s: Failed to open stream: %s in %s029.php on line %d

Warning: main() [unlink]: Attempt to unlink a file which path might be tainted in %s029.php on line %d

Warning: unlink(%s: %s in %s029.php on line %d

Warning: main() [readfile]: Attempt to read a file which path might be tainted in %s029.php on line %d

Warning: readfile(%s: Failed to open stream: %s in %s029.php on line %d

Warning: main() [opendir]: Attempt to open a directory which path might be tainted in %s029.php on line %d
%A
Warning: opendir(%s: Failed to open directory: %s in %s029.php on line %d
