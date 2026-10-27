<?php
// SINKLESS PROBE APP — rung experiment for "does the dangling core store land
// in application-visible data, and does object dispatch fire through the
// corrupted decode". This app's ONLY output primitive is echo: grep it —
// no system/exec/eval/passthru/proc_open/popen/shell_exec/pcntl/backtick.
// R1 (POST seed): plants int keys probe0..probeN + a Probe object in session.
// R2 (POST spray): fires the staleness corruption (frozen-counter shape).
// R3 (GET): decodes the persisted session and reports what SURVIVED:
//   ENTRY line  = the frozen-counter signature (condition, core-level)
//   KEYS line   = planted ints; a probe value equal to a stale counter =
//                 the core's dangling store landed on APP-VISIBLE data
//   PFIRE/DESTR = zend_call_function dispatch legs fired through decode
//                 (__unserialize / __destruct) — control-of-execution surface

class Probe {
    public $v = 0;
    public function __unserialize(array $d) {
        // fires during session_start() decode -> zend_call_function leg
        echo 'PFIRE UNSER v=', (int)($d['v'] ?? -1), "\n";
    }
    public function __destruct() {
        echo "DESTR FIRE\n";
    }
}

session_start();

// Window probe (sinkless pubstate arm): is session machinery ACTIVE at body
// phase, i.e. did the rfc1867 parse window pre-start it? Plus live ini shape.
echo 'WSTARTED=', (session_status() === PHP_SESSION_ACTIVE) ? 'ACTIVE' : 'NONE',
     ' CLEN=', (int)($_SERVER['CONTENT_LENGTH'] ?? 0),
     ' INI cleanup=', ini_get('session.upload_progress.cleanup'),
     ' minfreq=', ini_get('session.upload_progress.min_freq'),
     ' enabled=', ini_get('session.upload_progress.enabled'), "\n";

if (isset($_POST['seed'])) {
    foreach ((array)$_POST['seed'] as $kv) {
        $p = explode('|', (string)$kv, 2);
        if (count($p) === 2 && preg_match('/^probe\d{1,2}$/', $p[0])) {
            $_SESSION[$p[0]] = (int)$p[1];
        }
    }
    $o = new Probe();
    $o->v = 414141;               // planted value inside the object payload
    $_SESSION['pobj'] = $o;
}

$keys = array();
foreach ($_SESSION as $k => $val) {
    if (is_array($val) && str_starts_with((string)$k, 'upload_progress_')) {
        echo 'ENTRY BYTES=', (int)($val['bytes_processed'] ?? -1),
             ' CLEN=', (int)($val['content_length'] ?? -1), "\n";
    } elseif (is_int($val)) {
        $keys[(string)$k] = $val;
    }
}
ksort($keys);
echo 'KEYS ';
foreach ($keys as $k => $v) echo $k, '=', $v, ' ';
echo "\n";
echo 'POBJ=', isset($_SESSION['pobj']) ? 'yes' : 'no',
     ' POBJV=', (isset($_SESSION['pobj']) && $_SESSION['pobj'] instanceof Probe)
        ? (int)$_SESSION['pobj']->v : -99,
     ' N=', count($_SESSION), " OK\n";
