# Taint

[![Build Status](https://secure.travis-ci.org/laruence/php-taint.png)](http://travis-ci.org/laruence/php-taint)

php extension used to detect XSS codes(tainted string), And also can be used to spot sql injection vulnerabilities, shell inject, etc.

The idea is from https://wiki.php.net/rfc/taint, I implemented it in a php extension which make the patch no-needed.

Please note that do not enable this extension in product env.

## Requirement
- PHP-5.2 +

## Install
taint is an PECL extension, thus you can simply install it by:
````
pecl install taint
````
### Compile taint in Linux
````
$/path/to/phpize
$./configure --with-php-config=/path/to/php-config/
$make && make install
````

### Usage
When taint is enabled, if you pass a tainted string(comes from $_GET, $_POST or $_COOKIE) to some functions, taint will warn you about that.

````php
<?php
$a = trim($_GET['a']);

$file_name = '/tmp' .  $a;
$output    = "Welcome, {$a} !!!";
$var       = "output";
$sql       = "Select *  from " . $a;
$sql      .= "ooxx";

echo $output;

print $$var;

include($file_name);

mysql_query($sql);
````

The above example will output something similar to:
````
Warning: main() [function.echo]: Attempt to echo a string that might be tainted

Warning: main() [function.echo]: Attempt to print a string that might be tainted

Warning: include() [function.include]: File path contains data that might be tainted

Warning: mysql_query() [function.mysql-query]: SQL statement contains data that might be tainted
````
