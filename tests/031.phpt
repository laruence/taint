--TEST--
Clean data through all sinks must not trigger any taint warning
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
header("X-Taint-Test: clean");
echo "clean echo\n";
print "clean print\n";
printf("%s\n", "clean");
vprintf("%s\n", array("clean"));
print_r("clean"); echo "\n";
var_dump(unserialize(serialize(array(1, 2))));
echo "done\n";
?>
--EXPECTF--
clean echo
clean print
clean
clean
clean
array(2) {
  [0]=>
  int(1)
  [1]=>
  int(2)
}
done
