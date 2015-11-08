--TEST--
ISSUE #26 (PDO checking doesn't work)
--SKIPIF--
<?php
if (!extension_loaded('taint') || !extension_loaded('pdo_sqlite')) print 'skip not loaded';
?>
--INI--
taint.enable=1
--FILE--
<?php
$db = new PDO("sqlite::memory:");
$sql = "select 1";
taint($sql);
$stmt = $db->prepare($sql);
$stmt = $db->query($sql);
?>
--EXPECTF--
Warning: main() [PDO::prepare]: SQL statement contains data that might be tainted in %sissue026.php on line %d

Warning: main() [PDO::query]: SQL statement contains data that might be tainted in %sissue026.php on line %d
