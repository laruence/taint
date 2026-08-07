# Taint
[![linux](https://github.com/laruence/taint/actions/workflows/linux.yml/badge.svg)](https://github.com/laruence/taint/actions/workflows/linux.yml)

A PHP extension to detect XSS codes(tainted strings). It can also be used to spot SQL injection vulnerabilities, shell injection, etc.

The idea comes from https://wiki.php.net/rfc/taint, and I implemented it as a PHP extension, so no core patch is needed.

Please do not enable this extension in production environments, since it will slow down your app.

## Requirements
- PHP 8.0+ (`master` branch)
- PHP 7.x (`php7` branch, taint 2.1.x releases)
- PHP 5.x (`php5` branch, taint 1.x releases)

## How it works
Strings received from user input are marked "tainted" at request startup, and
the mark is tracked through string operations. When a tainted string reaches a
dangerous sink(output, SQL query, shell command, file path, ...), taint raises
a warning.

Taint sources: `$_GET`, `$_POST` and `$_COOKIE`.

## NOTE

Taint works by installing user opcode handlers and swapping internal function
handlers, so it conflicts with extensions that hook the executor or opcode
handlers as well, most notably **opcache** and **xdebug**. Do not enable
taint together with these extensions (the test suite disables both).

Taint is a detection tool for development use and is not designed for
production deployment anyway.

## Install
taint is a PECL extension, thus you can simply install it by:
````
pecl install taint
````
### Compile taint on Linux
````
$/path/to/phpize
$./configure --with-php-config=/path/to/php-config/
$make && make install
````
### Usage
When taint is enabled, if you pass a tainted string(which comes from $_GET, $_POST or $_COOKIE) to some dangerous functions, taint will warn you about that.

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

mysqli_query($link, $sql);
````

The above example will output something similar to:
````
Warning: main() [echo]: Attempt to echo a string that might be tainted in /path/to/script.php on line 10

Warning: main() [print]: Attempt to print a string that might be tainted in /path/to/script.php on line 12

Warning: main() [include]: File path contains data that might be tainted in /path/to/script.php on line 14

Warning: main() [mysqli_query]: SQL statement contains data that might be tainted in /path/to/script.php on line 16
````

### Detected sinks

| Category | Checked |
| --- | --- |
| Output | `echo`, `print`, `printf`, `vprintf`, `print_r`, `var_dump`, `var_export`, `exit`/`die` with a message, `file_put_contents()` to `php://output` |
| Filesystem | `fopen`, `unlink`, `file`, `readfile`, `file_get_contents`, `highlight_file`, `show_source`, `opendir`, `file_put_contents`, `copy`, `rename`, `move_uploaded_file`, `mkdir`, `rmdir`, `touch`, `include`, `include_once`, `require`, `require_once` |
| SQL | `mysqli_query`, `mysqli_prepare`, `mysqli_real_query`, `mysqli_multi_query`, `mysql_query`, `sqlite_query`, `sqlite_single_query`, `oci_parse`, `pg_query`, `pg_send_query`; methods `mysqli::query/prepare/real_query/multi_query`, `PDO::query/prepare/exec`, `SQLite3::query/prepare/exec`, `SQLiteDatabase::query/singleQuery` |
| Command | `exec`, `system`, `passthru`, `shell_exec`(including the backtick operator), `proc_open`, `popen` |
| Code execution | `eval`, dynamic calls `$func()`, `call_user_func`, `$obj->$method()`, array callables `[$obj, "m"]()` / `["C", "m"]()`, callback name passed to `preg_replace_callback` |
| Header/Cookie | `header`, `setcookie`, `setrawcookie` |
| Other | `unserialize`, `mail`(to, subject, additional_params and additional_headers) |

Checks are shallow on purpose: only top-level string arguments are inspected,
so dumping an *array* that contains tainted values does not warn.

### Taint propagation
The taint mark survives string concatenation(`.`, `"{$var}"` interpolation,
`.=`) and these functions(both the plain call and the PHP 8.4+ frameless fast
paths):

`trim`, `rtrim`, `ltrim`, `substr`, `strstr`, `str_replace`, `str_ireplace`,
`str_pad`, `sprintf`, `vsprintf`, `implode`, `join`, `explode`, `strtolower`,
`strtoupper`, `strval`, `dirname`, `basename`, `pathinfo`

Any other function call produces a fresh, unmarked string — including
escaping helpers such as `htmlspecialchars()`. Taint is a single,
context-independent bit by design: it is meant to over-report during
development rather than to understand which context a string is safe in.

### API

````php
<?php
/* manually mark variables as tainted (by reference) */
taint($a, $b);

/* check; only strings can be tainted, other types return false */
var_dump(is_tainted($a));

/* clear the mark. The bit lives on the string itself, so every
   copy/reference sharing the same string becomes clean at once */
untaint($a);
````

### INI settings

| Name | Default | Changeable | Description |
| --- | --- | --- | --- |
| `taint.enable` | `0` | `PHP_INI_SYSTEM` | master switch |
| `taint.error_level` | `512` (`E_USER_WARNING`) | `PHP_INI_ALL` | error level used for warnings |

If you need to hide the errors for a particular script, you can:
````
ini_set('taint.error_level', 0);
````

## Test
````
$/path/to/phpize
$./configure --with-php-config=/path/to/php-config
$make test
````
