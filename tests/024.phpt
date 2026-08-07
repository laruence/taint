--TEST--
Check $_GET, $_POST and $_COOKIE are marked tainted on request startup
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--CGI--
--GET--
a=from_get&n[0]=nested_get
--COOKIE--
c=from_cookie
--POST--
p=from_post
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
var_dump(is_tainted($_GET['a']));
var_dump(is_tainted($_GET['n'][0]));
var_dump(is_tainted($_COOKIE['c']));
var_dump(is_tainted($_POST['p']));

echo $_GET['a'];
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)

Warning: main() [echo]: Attempt to echo a string that might be tainted in %s024.php on line %d
from_get
