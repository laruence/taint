--TEST--
Command sinks: shell_exec, exec, system, passthru, popen, proc_open with valid commands
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php
$cmd = "ec" . "ho tainted-cmd";
taint($cmd);

shell_exec($cmd);
exec($cmd);
system($cmd);
passthru($cmd);
$h = popen($cmd, "r");
if ($h) {
    stream_get_contents($h);
    pclose($h);
}
$desc = array(0 => array("pipe", "r"), 1 => array("pipe", "w"));
$pipes = array();
$proc = proc_open($cmd, $desc, $pipes);
if (is_resource($proc)) {
    stream_get_contents($pipes[1]);
    fclose($pipes[0]);
    fclose($pipes[1]);
    proc_close($proc);
}

/* negative: clean command must not warn */
echo shell_exec("echo clean");
echo "done\n";
?>
--EXPECTF--
Warning: main() [shell_exec]: CMD statement contains data that might be tainted in %s045.php on line %d

Warning: main() [exec]: CMD statement contains data that might be tainted in %s045.php on line %d

Warning: main() [system]: CMD statement contains data that might be tainted in %s045.php on line %d
tainted-cmd

Warning: main() [passthru]: CMD statement contains data that might be tainted in %s045.php on line %d
tainted-cmd

Warning: main() [popen]: CMD statement contains data that might be tainted in %s045.php on line %d

Warning: main() [proc_open]: CMD statement contains data that might be tainted in %s045.php on line %d
clean
done
