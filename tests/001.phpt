--TEST--
Check for taint presence
--SKIPIF--
<?php if (!extension_loaded("taint")) print "skip"; ?>
--INI--
opcache.enable=0
opcache.enable_cli=0
xdebug.mode=off
--FILE--
<?php 
echo "taint extension is available";
/*
	you can add regression tests for your extension here

  the output of your test code has to be equal to the
  text in the --EXPECT-- section below for the tests
  to pass, differences between the output and the
  expected text are interpreted as failure

	see php5/README.TESTING for further information on
  writing regression tests
*/
?>
--EXPECT--
taint extension is available
