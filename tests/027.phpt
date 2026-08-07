--TEST--
Check propagation through object properties, method calls and static properties
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

class Holder {
    public $pub = "p";
    protected static $stat = "s";
    public function set($v) { $this->pub = $v; }
    public function get() { return $this->pub; }
    public static function setStat($v) { self::$stat = $v; }
    public static function getStat() { return self::$stat; }
}

$h = new Holder;
$h->pub = $a;
echo $h->pub, "\n";
echo $h->get(), "\n";

Holder::setStat($a);
echo Holder::getStat(), "\n";

$std = new stdClass;
$std->dynamic = $a;
echo $std->dynamic, "\n";
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s027.php on line %d
tainted string.

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s027.php on line %d
tainted string.

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s027.php on line %d
tainted string.

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s027.php on line %d
tainted string.
