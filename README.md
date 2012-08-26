# Taint

[![Build Status](https://secure.travis-ci.org/laruence/taint.png)](http://travis-ci.org/laruence/taint)

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
