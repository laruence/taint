--TEST--
Check SQLite3
--SKIPIF--
<?php if (!extension_loaded("taint") || !extension_loaded("sqlite3")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
class MySQLite3 extends SQLite3 {
}

$db = new MySQLite3(':memory:');

$sql = "select 1";
taint($sql);

$db->prepare($sql);
$db->query($sql);

--EXPECTF--
Warning: main() [SQLite3::prepare]: SQL statement contains data that might be tainted in %s018.php on line %d

Warning: main() [SQLite3::query]: SQL statement contains data that might be tainted in %s018.php on line %d
