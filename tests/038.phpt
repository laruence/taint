--TEST--
Exceptions in concat / function overrides leave taint fully functional
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
class Thrower {
    public function __toString() {
        throw new Exception("boom");
    }
}

try {
    $s = "pre" . new Thrower();
} catch (Exception $e) {
    echo "caught concat: ", $e->getMessage(), "\n";
}

try {
    trim(new Thrower());
} catch (Exception $e) {
    echo "caught trim: ", $e->getMessage(), "\n";
}

try {
    str_replace("a", "b", new Thrower());
} catch (Exception $e) {
    echo "caught str_replace: ", $e->getMessage(), "\n";
}

$a = "tainted string" . ".";
taint($a);
var_dump(is_tainted(trim($a)));
echo $a;
echo "\nstill functional\n";
?>
--EXPECTF--
caught concat: boom
caught trim: boom
caught str_replace: boom
bool(true)

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s038.php on line %d
tainted string.
still functional
