# Taint
[![linux](https://github.com/laruence/taint/actions/workflows/linux.yml/badge.svg)](https://github.com/laruence/taint/actions/workflows/linux.yml)
[![windows](https://github.com/laruence/taint/actions/workflows/windows.yml/badge.svg)](https://github.com/laruence/taint/actions/workflows/windows.yml)

A PHP extension to detect XSS codes(tainted strings). It can also be used to spot SQL injection vulnerabilities, shell injection, etc.

The idea comes from https://wiki.php.net/rfc/taint, and I implemented it as a PHP extension, so no core patch is needed.

Please do not enable this extension in production environments, since it will slow down your app.

> **EXPERIMENTAL.** Taint is a research-grade detection tool, not a security
> product. Detection coverage, warning behavior and INI settings may change
> between releases without any backward-compatibility guarantees.

## Requirements
- PHP 8.0+ (`master` branch)
- PHP 7.x ([php7 branch](https://github.com/laruence/taint/tree/php7), taint 2.1.x releases)
- PHP 5.x ([php5 branch](https://github.com/laruence/taint/tree/php5), taint 1.x releases)

## How it works
Strings received from user input are marked "tainted" at request startup, and
the mark is tracked through string operations. When a tainted string reaches a
dangerous sink (output, SQL query, shell command, file path, ...), taint
raises a warning.

Taint sources are: `$_GET`, `$_POST` and `$_COOKIE`.

## Design philosophy

- **One bit, no context.** The taint mark is a single bit stored on the
  string itself (`zend_string`), not on the variable. It carries no
  information about which context (HTML, SQL, shell, ...) the string will end
  up in, and taint never tries to analyze whether a value is "actually safe"
  for that context.
- **Over-report rather than stay silent.** Concatenation, interpolation and a
  whitelist of data-preserving string functions propagate the mark even when
  the result happens to be harmless. A warning means "user input reached this
  sink, go look at it", not "definitely exploitable". Noisy-but-auditable
  beats clever-but-silent.
- **Everything else clears the mark.** Any function taint does not explicitly
  understand — including escaping helpers like `htmlspecialchars()` — returns
  a fresh, unmarked string. Checks stay shallow on purpose: only top-level
  string arguments of sink calls are inspected.
- **Zero core changes.** The whole mechanism is implemented with user opcode
  handlers and internal-function handler swaps, so taint is a normal PECL
  extension that works on a stock PHP build. The price is that it conflicts
  with other extensions that hook the executor (see NOTE below).
- **Report, don't block.** Taint only raises warnings; it never alters or
  rejects data. It is a bug-finding instrument for developers, not a runtime
  defense.

## When to use

Good fits:

- Auditing an existing codebase: run your test suite, or drive the app
  manually, with taint enabled, and the warnings will point out paths where
  raw user input reaches an output, SQL, shell, filesystem or code-execution
  sink.
- Regression checks in development/QA environments before a release — XSS,
  SQL injection, command injection, file-path injection.
- Understanding how user input flows through an unfamiliar application.

Not a good fit:

- **Production.** The instrumentation slows every request down, forces the
  OPcache JIT off and does not mix with xdebug (see NOTE below), and the
  warnings themselves may leak request data into logs.
- **Runtime defense / WAF.** Taint reports, it does not block, and its
  context-independent bit cannot decide whether a value is really safe.
- **A substitute for escaping and parameterization.** A clean run means
  "nothing taint could see", never "provably secure".

## NOTE

Taint works by installing user opcode handlers and swapping internal function
handlers. That makes it incompatible with the **OPcache JIT** — but not with
OPcache itself:

- **OPcache (the opcode cache)** works fine together with taint.
- **OPcache JIT** cannot run at the same time: JIT-compiled code bypasses user
  opcode handlers, so the PHP engine refuses to start the JIT whenever an
  extension (like taint) has registered handlers. If `opcache.jit` is
  configured, PHP prints this warning at process startup and simply runs
  without the JIT:

  ````
  Warning: JIT is incompatible with third party extensions that setup user opcode handlers. JIT disabled.
  ````

  Taint itself keeps working normally — you just get no JIT speedups while it
  is loaded. This is enforced by the engine; there is nothing to configure.
- **Xdebug** hooks the executor as well; do not enable taint and xdebug
  together (the test suite runs with opcache and xdebug disabled).

Taint is a detection tool for development use and is not designed for
production deployment anyway.

## Install

### Install via PECL

Taint is a PECL extension, simply install it by:

````
$ pecl install taint
````

### Compile from source

````
$ /path/to/phpize
$ ./configure
$ make
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

For `sprintf`/`vsprintf` only `%s` specifiers carry the mark through —
`sprintf("%d", $t)` produces a clean string, since numeric specifiers emit
derived values, not the original bytes.

Any other function call produces a fresh, unmarked string — including
escaping helpers such as `htmlspecialchars()`. Taint is a single,
context-independent bit by design: it is meant to over-report during
development rather than to understand which context a string is safe in.

### API

Taint registers three global functions and no classes or constants.

````php
taint(string &$string, string &...$strings): bool
````

Manually mark variables as tainted (by reference). Always returns `true`.
Only non-empty strings are marked; other types and empty strings are silently
ignored. When `taint.enable` is off, this is a no-op (still returns `true`).
The mark lives on the string itself, so assignments just share it.

````php
untaint(string &$string, string &...$strings): bool
````

Clear the mark. Since the bit lives on the string itself, every copy/reference
sharing the same string becomes clean at once. Always returns `true`.

````php
is_tainted(string $string): bool
````

Check whether a value carries the taint mark. Only strings can be tainted,
other types return `false`. Always returns `false` when `taint.enable` is off.

````php
<?php
$a = $_GET['a'];
taint($a);          /* manually mark as tainted (by reference) */
var_dump(is_tainted($a));  /* true */
untaint($a);        /* clear the mark */
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

## License
Taint is distributed under the [PHP-3.01](https://www.php.net/license/3_01.txt) license.
