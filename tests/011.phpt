--TEST--
Check assign_ref and global keyword
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php 
function main() {
    global $var;
    $a = "tainted string" . ".";
    taint($a); //must use concat to make the string not a internal string(introduced in 5.4)
    $var = $a;
    echo $var;
}

main();
echo $var;
?>
--EXPECTF--
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s011.php on line %d
tainted string.
Warning: main() [echo]: Attempt to echo a string that might be tainted in %s011.php on line %d
tainted string.
