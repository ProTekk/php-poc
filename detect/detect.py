#!/usr/bin/env python3
"""detect.py — benign client-testing runner for php2shell_detect.php.

Modes:
  python3 detect.py                 # check the php on this machine (CLI)
  python3 detect.py --url URL [...] # check a live web venue (deploy the .php
                                    # to a docroot first; URL = its location)
  --probe                           # also run the behavioral probe: OOM-during-
                                    # parse arm + canary (the build-agnostic check
                                    # that sees through distro backports)

Exit codes: 0 fixed/mitigated, 2 vulnerable, 3 inconclusive, 4 unreachable/bad usage.
stdlib only; runs on Windows (py -3 detect.py) as well as Linux.
"""
import argparse, json, os, re, shutil, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
DET  = os.path.join(HERE, 'php2shell_detect.php')

def parse_size_mb(s):
    """memory_limit/post_max_size string -> MB float, or None if unknown/-1."""
    if s is None: return None
    s = str(s).strip()
    if s in ('', '-1'): return None
    m = re.match(r'^(\d+(?:\.\d+)?)([KMGT]?)B?$', s, re.I)
    if not m: return None
    n = float(m.group(1)); mult = {'':1, 'K':1/1024, 'M':1, 'G':1024, 'T':1024**2}[m.group(2).upper()]
    return n * mult

def parse_bytes(s):
    mb = parse_size_mb(s)
    return None if mb is None else int(mb * 1024 * 1024)

def parse_detect(text):
    """detector output -> dict of fields (first line) + extra lines list."""
    lines = [l for l in text.splitlines() if l.strip()]
    fields = {}
    extras = []
    for l in lines:
        if l.startswith('PHP2SHELL_DETECT|'):
            for kv in l.split('|')[1:]:
                if '=' in kv:
                    k, v = kv.split('=', 1); fields[k] = v
                else:
                    fields[l.split('|', 1)[0]] = ''
        else:
            extras.append(l)
    return fields, extras

def http_req(host, port, qs, body=b'', ctype=None, timeout=90, ssl=False, cookie=None):
    """One HTTP/1.1 request over a fresh socket (proven cve_driver pattern:
    origin-form target must start with '/'; mid-upload abort IS a signature)."""
    ctx = None
    if ssl:
        import ssl as _ssl
        ctx = _ssl._create_unverified_context()
    s = socket.create_connection((host, port), timeout=timeout)
    if ctx: s = ctx.wrap_socket(s, server_hostname=host)
    tgt = qs if qs.startswith('/') else '/' + qs
    ck = 'Cookie: %s\r\n' % cookie if cookie else ''
    if body == b'':
        head = "GET %s HTTP/1.1\r\nHost: x\r\n%sConnection: close\r\n\r\n" % (tgt, ck)
    else:
        head = ("POST %s HTTP/1.1\r\nHost: x\r\n%sContent-Type: %s\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n" % (tgt, ck, ctype, len(body)))
    sent_full = True
    try:
        s.sendall(head.encode() + body)
    except (BrokenPipeError, ConnectionAbortedError):
        sent_full = False
    data = b''
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    txt = data.decode('utf-8', 'replace')
    stat = txt.split('\r\n', 1)[0] if txt else ''
    rbody = txt.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in txt else ''
    return stat, rbody, sent_full

def classify(stat, body_txt, mid_upload_abort=False):
    """Exact signatures measured on stock 8.3.6 vs patched 8.3.36 (cve_driver, 10/21)."""
    if 'exhausted' in body_txt:
        return 'FIXED-SIG', True     # patched: delayed OOM surfaced visibly (vendor phpt symptom)
    if '500' in stat:
        return 'VULN-SIG', True      # unpatched: silent parse-time bailout, output discarded
    if mid_upload_abort and not body_txt:
        return 'VULN-SIG', True      # unpatched: bailout closed the connection mid-upload
    if '200' in stat and 'ARM|' in body_txt:
        return 'ARM-MISSED', False   # no OOM fired: body under limit / post_max_size truncation
    return 'UNKNOWN', False

def get_php(args):
    if args.php_bin: return args.php_bin
    return shutil.which('php') or 'php'

def local_mode(args):
    php = get_php(args)
    try:
        p = subprocess.run([php, DET], capture_output=True, timeout=30)
    except FileNotFoundError:
        print('ERR|php binary not found (%s) — set --php-bin or PATH' % php); return None, []
    if p.returncode not in (0, 2, 3):   # 2/3 are detector VERDICT codes, not errors
        print('ERR|php exited %d: %s' % (p.returncode, p.stderr.decode('utf-8','replace')[:200]))
    out = p.stdout.decode('utf-8', 'replace')
    notes = []
    pkg = None
    dp = shutil.which('dpkg')
    # cheap: query dpkg -l once and grep for php lines
    if dp and os.uname().sysname == 'Linux':
        try:
            r = subprocess.run([dp, '-l'], capture_output=True, timeout=20)
            rl = [l.split() for l in r.stdout.decode().splitlines() if len(l.split()) >= 3 and l.split()[0] == 'ii' and l.split()[1].startswith('php')]
            if rl:
                pkg = '; '.join('%s %s' % (x[1], x[2]) for x in rl[:6])
        except Exception:
            pass
    if pkg: notes.append('distro-pkgs: %s' % pkg)
    rpmq = shutil.which('rpm')
    if not pkg and rpmq:
        try:
            r = subprocess.run([rpmq, '-q', 'php', 'php-cli'], capture_output=True, timeout=15)
            rl = [l for l in r.stdout.decode().splitlines() if 'not installed' not in l]
            if rl: pkg = '; '.join(rl[:6]); notes.append('distro-pkgs: %s' % pkg)
        except Exception:
            pass
    return parse_detect(out) if out else (None, [])

def url_mode(args):
    from urllib.parse import urlparse
    u = urlparse(args.url)
    if u.scheme not in ('http', 'https') or not u.hostname:
        print('ERR|--url must be http(s)://host[:port]/path/detector.php'); return None, []
    host, port = u.hostname, u.port or (443 if u.scheme == 'https' else 80)
    path = u.path or '/'
    ssl = u.scheme == 'https'
    try:
        stat, body, _ = http_req(host, port, path + ('?%s' % u.query if u.query else ''), timeout=args.timeout, ssl=ssl)
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print('ERR|venue unreachable: %s' % e); return None, []
    if 'PHP2SHELL_DETECT' not in body:
        print('ERR|venue did not answer with a detector line (HTTP %s) — deploy php2shell_detect.php to the docroot and point --url at it' % (stat or '?'))
        print('BODY|%s' % body[:160].replace('\n', ' ')); return None, []
    fields, extras = parse_detect(body)
    notes = []
    xp = None
    return fields, extras, host, port, path, ssl

def probe(fields, host, port, path, ssl, args):
    mem_mb = parse_size_mb(fields.get('mem'))
    post_mb = parse_size_mb(fields.get('post'))
    if post_mb == 0: post_mb = None          # PHP convention: 0 = unlimited
    notes_pre = []
    if args.arm_mb:
        arm_mb = args.arm_mb
    elif mem_mb is None:
        print('PROBE|skipped|memory_limit=-1/unlimited — OOM arm is not benign here; run the probe on a capped venue'); return 'SKIPPED'
    else:
        arm_mb = mem_mb * 1.5 + 1
        if post_mb is not None and arm_mb > post_mb:
            arm_mb = post_mb * 0.95           # stay inside post_max_size: truncation would silently neuter the arm
            if arm_mb <= mem_mb:
                print('PROBE|skipped|post_max_size=%s truncates the plain-body arm below memory_limit=%s — parse-phase OOM unreachable (raising post_max_size is the vendor arm recipe, but that is a config change, not a benign probe)' % (fields.get('post'), fields.get('mem')))
                return 'SKIPPED'
        if arm_mb > args.arm_cap:
            print('PROBE|skipped|arm body %.0fMB exceeds --arm-cap=%d (generous production limit; upload size is the benignity budget)' % (arm_mb, args.arm_cap)); return 'SKIPPED'
    sid = 'detectprobe000000000000000%d' % (os.getpid() % 997)  # [0-9a-v] only: 8.3 sid vetting
    qs0 = '%s?canary=1&PHPSESSID=%s' % (path, sid)
    try:
        stat0, body0, _ = http_req(host, port, qs0, timeout=args.timeout, ssl=ssl)
    except OSError as e:
        print('PROBE|skipped|baseline canary unreachable: %s' % e); return 'SKIPPED'
    pid0 = re.search(r'pid=(\d+)', body0).group(1) if 'pid=' in body0 else '?'
    arm_body = ('a=' + 'a' * int(arm_mb * 1024 * 1024)).encode()
    try:
        stA, bA, sent_full = http_req(host, port, '%s?arm=1&PHPSESSID=%s' % (path, sid),
                                      body=arm_body, ctype='application/x-www-form-urlencoded',
                                      timeout=max(args.timeout, 120), ssl=ssl)
    except socket.timeout:
        stA, bA, sent_full = 'TIMEOUT', '', False   # venue wedged mid-upload = stock symptom shape
    sig, conclusive = classify(stA, bA, mid_upload_abort=not sent_full)
    print('PROBE-ARM|mb=%.0f|status=%r|sent_full=%s|sig=%s' % (arm_mb, stA or 'conn-reset', sent_full, sig))
    # canary on the same venue after the arm (619 consumer read + worker-regime note)
    try:
        stat1, body1, _ = http_req(host, port, '%s?canary=1&PHPSESSID=%s' % (path, sid), timeout=args.timeout, ssl=ssl)
        pid1 = re.search(r'pid=(\d+)', body1).group(1) if 'pid=' in body1 else '?'
        leaked = ''
        m = re.search(r'leaked=([\w-]+)', body1)
        if m: leaked = '|canary_warning=%s' % m.group(1)
        print('PROBE-CANARY|pid_before=%s|pid_after=%s%s' % (pid0, pid1, leaked))
        if pid1 != '?' and pid0 != '?' and pid1 != pid0:
            print('PROBE-NOTE|worker respawned across the arm (FPM/cgi regime: bailout ended the worker — vuln-consistent; benign worker churn)')
    except OSError as e:
        print('PROBE-CANARY|skipped|%s' % e)
    return sig

def pubstate(fields, host, port, path, ssl, args):
    """Chain tier: one ~1KB multipart POST carrying the configured progress
    field (proven stock_rce R3 shape); the detector reports whether its own
    progress entry was published in-request — the precondition the stock-config
    lever (and our chains) run on. No dial-back, no ini, ~1KB on the wire."""
    if fields.get('up_en') in ('0', "'0'", 'false', 'False'):
        print('CHAIN|skipped|upload_progress disabled — lever door closed by config'); return 'IDLE'
    name = fields.get('up_name') or 'PHP_SESSION_UPLOAD_PROGRESS'
    if name == 'unset': name = 'PHP_SESSION_UPLOAD_PROGRESS'
    sid = 'detectpspbstate%013d' % (os.getpid() % 10**13)   # [0-9a-v] only, 8.3 sid vetting
    B = '----dps'
    prog_field = ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\nps\r\n'
                  '--%s\r\nContent-Disposition: form-data; name="file"; filename="w.bin"\r\n'
                  'Content-Type: application/octet-stream\r\n\r\n' % (B, name, B)).encode()
    # PACED, not instant: two compiled realities drive this shape —
    # (a) min_freq defaults to 1 SECOND: a sub-second upload publishes no
    #     progress entry (fact #450 lesson), so the drip must exceed ~1s;
    # (b) stock rfc1867 engagement requires a known Content-Length > 0
    #     (chunked=-1 doesn't engage the unpatched path), so no chunked
    #     encoding: known length, body dribbled over the wire in drips.
    tail = ('\r\n--%s--\r\n' % B).encode()
    body = prog_field + b'A' * 1024 + tail
    def drip(sock):
        try:
            n = len(body)
            q = (n + 3) // 4
            parts = (body[:q], body[q:2*q], body[2*q:3*q], body[3*q:])
            for i, part in enumerate(parts):
                if i: time.sleep(0.45)      # body completes at ~1.35s of flight:
                sock.sendall(part)          # a min_freq=1s venue ticks its first publish
        except (BrokenPipeError, ConnectionResetError):
            return False
        return True
    ctx = None
    if ssl:
        import ssl as _ssl
        ctx = _ssl._create_unverified_context()
    try:
        s = socket.create_connection((host, port), timeout=args.timeout)
        if ctx: s = ctx.wrap_socket(s, server_hostname=host)
        tgt = ('%s?pubstate=1' % path)
        s.sendall(("POST %s HTTP/1.1\r\nHost: x\r\nCookie: PHPSESSID=%s\r\n"
                   "Content-Type: multipart/form-data; boundary=%s\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n"
                   % (tgt, sid, B, len(body))).encode())
        drip(s)
        data = b''
        try:
            while True:
                c = s.recv(65536)
                if not c: break
                data += c
        except socket.timeout:
            pass
        s.close()
    except OSError as e:
        print('CHAIN|skipped|pubstate POST failed: %s' % e); return None
    rbody = data.decode('utf-8', 'replace').split('\r\n\r\n', 1)[1] if b'\r\n\r\n' in data else ''
    m = re.search(r'PUBSTATE\|cl=(\d+)\|pre=(\d)\|entry=(\S*?)\|sess=(\d+)\|gate=([01])', rbody)
    if not m:
        print('CHAIN|unknown|no PUBSTATE line in reply: %s' % rbody[:80].replace('\n', ' ')); return None
    gate = m.group(5)
    print('CHAIN-PUBSTATE|gate=%s|entry=%s|pre_start=%s|content_length=%s' % (gate, m.group(3), m.group(2), m.group(1)))
    if gate == '0':
        # Read-back arm: unpatched mod_php hides the parse-window entry from app
        # time, but under cleanup=0 it survives in the session file (WP-oracle
        # pattern). One ~1KB GET on the same sid.
        try:
            st2, rb2, _ = http_req(host, port, '%s?readstate=1' % path,
                                   cookie='PHPSESSID=%s' % sid, timeout=args.timeout, ssl=ssl)
            m2 = re.search(r'READSTATE\|entry=(\S*?)\|sess=\d+\|gate=([01])', rb2)
            if m2:
                print('CHAIN-READSTATE|gate=%s|entry=%s' % (m2.group(2), m2.group(1)))
                if m2.group(2) == '1':
                    return 'ARMED'
        except OSError:
            pass
    if gate == '1':
        return 'ARMED'
    # Not observable in-request. Under a stock cleanup=1 regime the entry
    # "lives and dies inside the parse window" (measured 10/21) — absence is
    # NOT evidence the lever door is closed. Under cleanup=0 we gave the door
    # every chance to show itself and it didn't: that reads as IDLE honestly.
    cleanup = fields.get('up_cleanup', '')
    if cleanup not in ('0', "'0'", 'false', 'False'):
        return 'LIKELY'
    return 'IDLE'

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--url', help='live venue: http(s)://host:port/path/detector.php')
    ap.add_argument('--probe', action='store_true', help='run the behavioral probe (HTTP venues)')
    ap.add_argument('--no-chain', action='store_true', help='skip the pubstate chain tier (1KB POST, runs by default on --url venues)')
    ap.add_argument('--arm-mb', type=float, default=None, help='override arm body size (MB)')
    ap.add_argument('--arm-cap', type=int, default=48, help='skip probe if computed arm > this MB (default 48)')
    ap.add_argument('--php-bin', default=None, help='php binary for local mode')
    ap.add_argument('--timeout', type=int, default=60)
    args = ap.parse_args()

    if args.url:
        got = url_mode(args)
        if got[0] is None: return 4
        fields, extras, host, port, path, ssl = got
    else:
        fields, extras = local_mode(args)
        if fields is None: return 4
        host = port = path = ssl = None

    for l in extras: print(l)

    verdict = fields.get('verdict', 'UNKNOWN')
    notes = []
    up_en = fields.get('up_en', '')
    if up_en in ('0', "'0'", 'false', 'False', ''):
        notes.append('upload_progress disabled: demonstrated rfc1867 door CLOSED by config (patch still required for the general-decode class)')
    if verdict in ('VULN', 'VULN-EOL'):
        notes.append('lineage verdict is backport-blind: RHEL/Amazon/SRU builds patch without bumping the version — confirm with --probe')

    psig = None
    if args.probe:
        if not args.url:
            print('PROBE|skipped|--probe needs --url (the arm rides the live venue parse window)')
        else:
            psig = probe(fields, host, port, path, ssl, args)
    else:
        print('PROBE|not-run|pass --probe for the build-agnostic behavioral check')

    chain = None
    if not args.no_chain:
        if args.url:
            chain = pubstate(fields, host, port, path, ssl, args)
        else:
            print('CHAIN|not-run|the pubstate tier rides the venue parse window; needs --url')

    # combine: probe outranks lineage (that's the whole point of the probe)
    final, conf = verdict, 'lineage-only'
    if psig == 'FIXED-SIG':
        final, conf = 'FIXED', 'probe-confirmed'
    elif psig == 'VULN-SIG':
        final, conf = 'VULN', 'probe-confirmed'
    elif psig in ('ARM-MISSED', 'UNKNOWN'):
        final, conf = 'INCONCLUSIVE', 'probe-armed-but-did-not-fire'
    elif psig == 'SKIPPED':
        conf = 'lineage-only (probe skipped)'

    mitigated = 'door-closed-by-config' if up_en in ('0', "'0'", 'false', 'False', '') else ''
    print('DETECT-VERDICT|verdict=%s|static=%s|probe=%s|confidence=%s|chain=%s|php=%s|sapi=%s%s' % (
        final, verdict, psig or 'not-run', conf, chain or 'not-run',
        fields.get('v', '?'), fields.get('sapi', '?'),
        ('|mitigation=' + mitigated) if mitigated else ''))
    if chain == 'ARMED':
        print('CHAIN-VERDICT|state=ARMED|basis=progress-entry-observed|note=stock-config lever precondition fires: our chains are armed on this venue (RCE leg stays app-sink-specific; frozen-counter forensics additionally needs cleanup=0)')
    elif chain == 'LIKELY':
        print('CHAIN-VERDICT|state=LIKELY|basis=door-open-unobservable|note=upload_progress enabled and venue accepts paced plants, but a stock cleanup=1 regime erases the progress entry inside the parse window (measured behavior) — lever door open, entry not observable; treat as chain-capable pending an in-window app sink check')
    for n in notes: print('NOTE|' + n)

    cve_vuln = final in ('VULN', 'VULN-EOL')
    if chain == 'ARMED' or cve_vuln:
        return 2
    if final == 'INCONCLUSIVE':
        return 3
    if final in ('FIXED', 'NO-TRIGGER'):
        return 0
    return 3

if __name__ == '__main__':
    sys.exit(main())
