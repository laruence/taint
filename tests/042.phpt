--TEST--
SQL sinks: SQLite3::exec, PDO::exec, mysqli real_query/multi_query, pg_query
--SKIPIF--
<?php
if (!extension_loaded("taint")) print "skip";
if (!extension_loaded("sqlite3") || !extension_loaded("pdo_sqlite")) print "skip";
if (!extension_loaded("mysqli") || !extension_loaded("pgsql")) print "skip";
?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$a = "tainted string" . ".";
taint($a);

$db = new SQLite3(":memory:");
$db->exec($a);
$db->query($a);
$db->exec("CREATE TABLE t (x)"); /* negative */

$pdo = new PDO("sqlite::memory:");
try { $pdo->exec($a); } catch (Throwable $e) {}
try { $pdo->query($a); } catch (Throwable $e) {}
$pdo->exec("CREATE TABLE t (x)"); /* negative */

try { $m = mysqli_init(); mysqli_real_query($m, $a); } catch (Throwable $e) {}
try { $m = mysqli_init(); mysqli_multi_query($m, $a); } catch (Throwable $e) {}
try { $m = mysqli_init(); $m->real_query($a); } catch (Throwable $e) {}
try { $m = mysqli_init(); $m->multi_query($a); } catch (Throwable $e) {}

try { pg_query(false, $a); } catch (Throwable $e) {}
try { pg_send_query(false, $a); } catch (Throwable $e) {}
echo "done\n";
?>
--EXPECTF--
Warning: main() [SQLite3::exec]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: SQLite3::exec(): near %s in %s042.php on line %d

Warning: main() [SQLite3::query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: SQLite3::query(): near %s in %s042.php on line %d

Warning: main() [PDO::exec]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [PDO::query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [mysqli_real_query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [mysqli_multi_query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [mysqli::real_query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [mysqli::multi_query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [pg_query]: SQL statement contains data that might be tainted in %s042.php on line %d

Warning: main() [pg_send_query]: SQL statement contains data that might be tainted in %s042.php on line %d
done
