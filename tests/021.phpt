--TEST--
preg_replace() should untaint a string
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
taint.enable=1
--FILE--
<?php
class request {
    function get() {
        $a = "a" ."";
        taint($a);
        
        return $a;    
    }
}

$req = new request();
var_dump(is_tainted($req->get()));

$a = preg_replace('/[^a-z_\-]/i', '', $req->get());

var_dump(is_tainted($a));
--EXPECTF--
bool(true)
bool(false)

