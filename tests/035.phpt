--TEST--
Dynamic calls: $obj->$method(), array callables, clean names stay silent
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
class C {
    public function hello() { return "hi"; }
    public static function world() { return "world"; }
}
$o = new C();

$m = "hel" . "lo";
taint($m);
echo $o->$m(), "\n";

$cb = array($o, "hel" . "lo");
taint($cb[1]);
echo $cb(), "\n";

$cb2 = array("C", "world");
taint($cb2[0]);
echo $cb2(), "\n";

$clean = "hello";
echo $o->$clean(), "\n";
?>
--EXPECTF--
Warning: main() [fcall]: Attempt to call a method which name might be tainted in %s035.php on line %d
hi

Warning: main() [fcall]: Attempt to call a method which name might be tainted in %s035.php on line %d
hi

Warning: main() [fcall]: Attempt to call a method of a class which name might be tainted in %s035.php on line %d
world
hi
