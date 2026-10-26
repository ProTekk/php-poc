<?php
// php2shell_detect.php — benign detector for the PHP upload-progress
// CVE pair (CVE-2026-109618 / CVE-2026-109619, "PHP2Shell").
// Single file, no deps, PHP 5.4+ (upload_progress exists from 5.4),
// Windows/Linux/macOS-safe: no posix, no pcntl, no exec of external
// binaries. Run from CLI (checks THIS php) or drop in a docroot and
// browse/curl (checks the SERVER's php).
//
// Tiers:
//   1. version lineage vs the vendor fix floors (GHSA-w8hw-w9fx-j79w /
//      GHSA-6wmf-4rv5-p3rp: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; source-only
//      backport branches for 7.4/8.0/8.1 = no binaries ever)
//   2. config gate: session.upload_progress.enabled (compiled default is
//      ON across modern builds; enabled=0 closes the demonstrated door)
//   3. behavioral probe lives in the runner (detect.py): OOM-during-parse
//      arm + canary, build-agnostic — the only check that survives distro
//      backport shenanigans (RHEL/Amazon/SRU rebuild without a version bump)
//
// Verdicts here are UPSTREAM-LINEAGE verdicts; the runner notes distro-
// backport blindness and confirms with the probe.

error_reporting(E_ALL);
@ini_set('display_errors', '1');

// ---- fix-floor table (upstream lineage) -------------------------------
$floors = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');
$mm = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$floor = '';
if (version_compare(PHP_VERSION, '5.4.0', '<')) {
    $verdict = 'NO-TRIGGER';   // no session.upload_progress before 5.4
    $floor   = 'n/a (<5.4)';
} elseif (version_compare(PHP_VERSION, '8.2.0', '<')) {
    $verdict = 'VULN-EOL';     // 5.4–8.1: in-range, never patched in binaries
    $floor   = 'none (source-only backports)';
} elseif (version_compare(PHP_VERSION, '8.6.0', '>=')) {
    $verdict = 'FIXED';        // 8.6+ lineage descends from the fix
    $floor   = 'n/a (8.6+ post-fix lineage)';
} elseif (isset($floors[$mm])) {
    $floor   = $floors[$mm];
    $verdict = version_compare(PHP_VERSION, $floors[$mm], '>=') ? 'FIXED' : 'VULN';
} else {
    $verdict = 'UNKNOWN';      // future unknown branch below 8.6 floor table
    $floor   = 'unmapped branch';
}

// ---- config gate (compiled defaults measured identical on vanilla
// 8.5.12 and Ubuntu noble 8.3.6: enabled=1, name=PHP_SESSION_UPLOAD_PROGRESS)
$up_en      = ini_get('session.upload_progress.enabled');
$up_name    = ini_get('session.upload_progress.name');
$up_cleanup = ini_get('session.upload_progress.cleanup');
$up_minfreq = ini_get('session.upload_progress.min_freq');
$up_freq    = ini_get('session.upload_progress.freq');

// ---- platform (Windows-safe: PHP_OS_FAMILY is 7.2+, guarded for older) --
$osfam = defined('PHP_OS_FAMILY') ? PHP_OS_FAMILY : PHP_OS;
$zts   = defined('PHP_ZTS') ? (string)(int)PHP_ZTS : '0';  // constant is always defined; its VALUE is the flag

$out = array();
$out[] = 'PHP2SHELL_DETECT|v=' . PHP_VERSION . '|vid=' . PHP_VERSION_ID . '|mm=' . $mm
       . '|floor=' . $floor . '|verdict=' . $verdict
       . '|sapi=' . php_sapi_name()
       . '|osfam=' . $osfam . '|zts=' . $zts
       . '|ini=' . (php_ini_loaded_file() !== null && php_ini_loaded_file() !== '' ? php_ini_loaded_file() : 'none')
       . '|mem=' . ini_get('memory_limit')
       . '|post=' . ini_get('post_max_size')
       . '|up_en=' . var_export($up_en === '' ? null : $up_en, true)
       . '|up_name=' . ($up_name === '' ? 'unset' : $up_name)
       . '|up_cleanup=' . var_export($up_cleanup === '' ? null : $up_cleanup, true)
       . '|up_minfreq=' . var_export($up_minfreq === '' ? null : $up_minfreq, true)
       . '|up_freq=' . var_export($up_freq === '' ? null : $up_freq, true);
if (isset($_SERVER['SERVER_SOFTWARE'])) {
    $out[] = 'SERVER|' . str_replace('|', ' ', $_SERVER['SERVER_SOFTWARE']);
}

// ---- arms ------------------------------------------------------------
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'CLI';

if (isset($_GET['arm']) && $method === 'POST') {
    // Probe arm: big form-urlencoded body forces a parse-phase memory_limit
    // fatal. On UNPATCHED lineage the bailout discards the output (silent
    // 500 / connection closed mid-upload); on PATCHED lineage the OOM is
    // deferred to a safe point and the response shows it. The RECEIVED echo
    // below is deliberately last: it survives only on patched builds.
    $n = (isset($_POST['a']) && is_string($_POST['a'])) ? strlen($_POST['a']) : 0;
    $out[] = 'ARM|method=POST|received=' . $n . '|mem=' . ini_get('memory_limit');
} elseif (isset($_GET['arm'])) {
    $out[] = 'ARM|method=GET|mem=' . ini_get('memory_limit');
}

if (isset($_GET['canary'])) {
    // Vendor canary (sapi/cli/tests/oom_*_next_request shape): class-entry
    // machinery + a raised warning, read on a follow-up request to the same
    // worker to see state a previous bailout may have leaked.
    $cls = null; $err = null;
    $buf = ob_start();
    try {
        spl_autoload_register(function ($class) { eval("class $class {}"); });
        $cls = get_class(new Foo);
    } catch (Exception $e) { $err = get_class($e) . ':' . $e->getMessage(); }
      catch (Error $e)    { $err = get_class($e) . ':' . $e->getMessage(); }
    // (two catch blocks instead of Throwable: stays parseable on 5.x)
    trigger_error('Bar', E_USER_WARNING);
    $warn = ob_get_clean();
    $out[] = 'CANARY|pid=' . getmypid() . '|class=' . ($cls !== null ? $cls : 'throwable:' . $err)
           . '|leaked=' . (strpos($warn, 'Bar') !== false ? 'warning-visible' : 'warning-missing');
}

echo implode("\n", $out), "\n";

// CLI exit code for batch/CMD automation: 0 fixed/not-affected, 2 vulnerable,
// 3 unknown. (HTTP mode: the web server owns the status line; ignored there.)
if (php_sapi_name() === 'cli') {
    exit($verdict === 'FIXED' || $verdict === 'NO-TRIGGER' ? 0 : ($verdict === 'UNKNOWN' ? 3 : 2));
}
