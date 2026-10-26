#!/usr/bin/env python3
"""detect.py — benign client-testing runner for php2shell_detect.php.

Default output is HUMAN: a one-line verdict plus a few plain lines, with all
machine-parseable detail written to a log file (path printed at the end).
  python3 detect.py                    # check the php on this machine (CLI)
  python3 detect.py --url URL --probe  # check a live web venue (deploy the
                                       # .php to a docroot first)
  --raw                                # machine pipe-format to stdout, no log
Exit codes: 0 no findings, 2 vulnerable (CVE lineage OR chain ARMED),
3 inconclusive, 4 unreachable/bad usage. stdlib only; Windows-safe (py -3).
"""
import argparse, os, re, shutil, socket, subprocess, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DET  = os.path.join(HERE, 'php2shell_detect.php')

MLINES = []          # machine-channel lines -> log file
RAW = False          # --raw: machine lines straight to stdout, no log
USE_COLOR = False    # resolved in main() from tty/flags/env

def init_color(args, stream):
    """ANSI color if: --color forced, or (stdout is a tty and NO_COLOR unset
    and TERM is not dumb). --nocolor kills it. Windows 10+ consoles get VT
    mode via the os.system('') bootstrap."""
    global USE_COLOR
    if args.nocolor:
        USE_COLOR = False
    elif args.color:
        USE_COLOR = True
    else:
        USE_COLOR = (stream.isatty()
                     and not os.environ.get('NO_COLOR')
                     and os.environ.get('TERM') != 'dumb')
    if USE_COLOR and os.name == 'nt':
        os.system('')   # enable ANSI VT processing on Windows consoles

def c(s, col):
    return ('\033[%sm' % col) + s + '\033[0m' if USE_COLOR else s

# classic 16-color slots: 31 red, 32 green, 33 yellow, 36 cyan, 90 bright-black (dim)
RED, GRN, YEL, CYA, DIM = '31', '32', '33', '36', '90'
BRED, BGRN, BYEL, BCYA, BOLD = '1;31', '1;32', '1;33', '1;36', '1'

def ml(msg):
    """Emit one machine line (pipe-formatted)."""
    if RAW:
        print(msg)
    else:
        MLINES.append(msg)

def human(msg):
    print(msg)

def parse_size_mb(s):
    """memory_limit/post_max_size string -> MB float, or None if unknown/-1."""
    if s is None: return None
    s = str(s).strip()
    if s in ('', '-1'): return None
    m = re.match(r'^(\d+(?:\.\d+)?)([KMGT]?)B?$', s, re.I)
    if not m: return None
    n = float(m.group(1)); mult = {'':1, 'K':1/1024, 'M':1, 'G':1024, 'T':1024**2}[m.group(2).upper()]
    return n * mult

def parse_detect(text):
    """detector output -> dict of fields (first line) + extra lines list."""
    fields, extras = {}, []
    for l in [x for x in text.splitlines() if x.strip()]:
        if l.startswith('PHP2SHELL_DETECT|'):
            for kv in l.split('|')[1:]:
                if '=' in kv:
                    k, v = kv.split('=', 1); fields[k] = v
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
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
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

def local_mode(args):
    php = args.php_bin or shutil.which('php') or 'php'
    try:
        p = subprocess.run([php, DET], capture_output=True, timeout=30)
    except FileNotFoundError:
        human('  php binary not found (%s) — set --php-bin or PATH' % php); return None
    if p.returncode not in (0, 2, 3):   # 2/3 are detector VERDICT codes, not errors
        human('  php exited unexpectedly (%d): %s' % (p.returncode, p.stderr.decode('utf-8', 'replace')[:200]))
    out = p.stdout.decode('utf-8', 'replace')
    for l in out.splitlines():
        if l.startswith('PHP2SHELL_DETECT|') or l.startswith('SERVER|'): ml(l)
    fields, _ = parse_detect(out)
    pkg = None
    dp = shutil.which('dpkg')
    if dp and os.name == 'posix' and os.uname().sysname == 'Linux':
        try:
            r = subprocess.run([dp, '-l'], capture_output=True, timeout=20)
            rl = [l.split() for l in r.stdout.decode().splitlines()
                  if len(l.split()) >= 3 and l.split()[0] == 'ii' and l.split()[1].startswith('php')]
            if rl: pkg = '; '.join('%s %s' % (x[1], x[2]) for x in rl[:6])
        except Exception:
            pass
    if not pkg:
        rpmq = shutil.which('rpm')
        if rpmq:
            try:
                r = subprocess.run([rpmq, '-q', 'php', 'php-cli'], capture_output=True, timeout=15)
                rl = [l for l in r.stdout.decode().splitlines() if 'not installed' not in l]
                if rl: pkg = '; '.join(rl[:6])
            except Exception:
                pass
    if pkg:
        ml('PKG|%s' % pkg)
        first = pkg.split(';')[0]
        more = pkg.count(';')
        human('  distro packages: %s%s' % (first, (' (+%d more)' % more) if more else ''))
    return fields if out else None

def url_mode(args):
    from urllib.parse import urlparse
    u = urlparse(args.url)
    if u.scheme not in ('http', 'https') or not u.hostname:
        human('  --url must be http(s)://host[:port]/path/detector.php'); return None
    host, port = u.hostname, u.port or (443 if u.scheme == 'https' else 80)
    path = u.path or '/'
    ssl = u.scheme == 'https'
    try:
        stat, body, _ = http_req(host, port, path + ('?%s' % u.query if u.query else ''), timeout=args.timeout, ssl=ssl)
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        human('  venue unreachable: %s' % e); return None
    if 'PHP2SHELL_DETECT' not in body:
        human('  venue did not answer with a detector line (HTTP %s) — deploy php2shell_detect.php to the docroot and point --url at it' % (stat or '?'))
        human('  first reply: %s' % body[:120].replace('\n', ' ')); return None
    fields, extras = parse_detect(body)
    for l in extras:
        if l.startswith('SERVER|'):
            human('  server: %s' % l.split('|', 1)[1])
    ml('SERVER-HOST|%s|http_status=%s' % (host, stat or '?'))
    return (fields, host, port, path, ssl)

def probe(fields, host, port, path, ssl, args):
    mem_mb = parse_size_mb(fields.get('mem'))
    post_mb = parse_size_mb(fields.get('post'))
    if post_mb == 0: post_mb = None          # PHP convention: 0 = unlimited
    if args.arm_mb:
        arm_mb = args.arm_mb
    elif mem_mb is None:
        ml('PROBE|skipped|memory_limit=-1/unlimited — OOM arm not benign here')
        human('  probe: skipped — memory_limit is unlimited (an OOM arm would be unbounded, not benign)'); return 'SKIPPED'
    else:
        arm_mb = mem_mb * 1.5 + 1
        if post_mb is not None and arm_mb > post_mb:
            arm_mb = post_mb * 0.95         # truncation would silently neuter the arm
            if arm_mb <= mem_mb:
                ml('PROBE|skipped|post_max_size=%s truncates arm below memory_limit=%s' % (fields.get('post'), fields.get('mem')))
                human('  probe: skipped — post_max_size=%s truncates the arm below memory_limit=%s (raising it is a config change, not a probe)' % (fields.get('post'), fields.get('mem')))
                return 'SKIPPED'
        if arm_mb > args.arm_cap:
            ml('PROBE|skipped|arm body %.0fMB exceeds --arm-cap=%d' % (arm_mb, args.arm_cap))
            human('  probe: skipped — arm body %.0fMB exceeds the %dMB benignity cap (generous production memory limit)' % (arm_mb, args.arm_cap))
            return 'SKIPPED'
    sid = 'detectprobe000000000000000%d' % (os.getpid() % 997)  # [0-9a-v] only: 8.3 sid vetting
    try:
        stat0, body0, _ = http_req(host, port, '%s?canary=1&PHPSESSID=%s' % (path, sid), timeout=args.timeout, ssl=ssl)
    except OSError as e:
        ml('PROBE|skipped|baseline canary unreachable: %s' % e); human('  probe: skipped — canary unreachable'); return 'SKIPPED'
    pid0 = re.search(r'pid=(\d+)', body0).group(1) if 'pid=' in body0 else '?'
    arm_body = ('a=' + 'a' * int(arm_mb * 1024 * 1024)).encode()
    try:
        stA, bA, sent_full = http_req(host, port, '%s?arm=1&PHPSESSID=%s' % (path, sid),
                                      body=arm_body, ctype='application/x-www-form-urlencoded',
                                      timeout=max(args.timeout, 120), ssl=ssl)
    except socket.timeout:
        stA, bA, sent_full = 'TIMEOUT', '', False   # venue wedged mid-upload = stock symptom shape
    sig, conclusive = classify(stA, bA, mid_upload_abort=not sent_full)
    ml('PROBE-ARM|mb=%.0f|status=%r|sent_full=%s|sig=%s' % (arm_mb, stA or 'conn-reset', sent_full, sig))
    try:
        stat1, body1, _ = http_req(host, port, '%s?canary=1&PHPSESSID=%s' % (path, sid), timeout=args.timeout, ssl=ssl)
        pid1 = re.search(r'pid=(\d+)', body1).group(1) if 'pid=' in body1 else '?'
        leaked = ''
        m = re.search(r'leaked=([\w-]+)', body1)
        if m: leaked = '|canary_warning=%s' % m.group(1)
        ml('PROBE-CANARY|pid_before=%s|pid_after=%s%s' % (pid0, pid1, leaked))
        if pid1 != '?' and pid0 != '?' and pid1 != pid0:
            ml('PROBE-NOTE|worker respawned across the arm (FPM/cgi regime — benign churn, vuln-consistent)')
    except OSError as e:
        ml('PROBE-CANARY|skipped|%s' % e)
    hum = {'FIXED-SIG': 'patched behavior observed (visible delayed memory-limit error)',
           'VULN-SIG': 'unpatched behavior observed (silent 500 / dropped connection under memory pressure)',
           'ARM-MISSED': 'arm did not trigger a memory-limit condition (body under venue limits)',
           'UNKNOWN': 'probe result ambiguous — see log'}
    pcol = {'VULN-SIG': RED, 'FIXED-SIG': GRN}.get(sig, YEL)
    human('  %s' % c('probe: ' + hum.get(sig, sig), pcol))
    return sig

def pubstate(fields, host, port, path, ssl, args):
    """Chain tier: paced ~1.3KB multipart plant carrying the configured progress
    field (Content-Length known — chunked never engages stock rfc1867; ~1.35s of
    flight — min_freq defaults to 1 SECOND and sub-second uploads publish no
    entry), then one same-sid read-back GET. Reports whether the upload-progress
    entry gets published: the precondition our stock-config lever runs on."""
    if fields.get('up_en') in ('0', "'0'", 'false', 'False'):
        ml('CHAIN|skipped|upload_progress disabled'); human('  %s' % c('chain: upload_progress is disabled — lever door closed by config', DIM)); return 'IDLE'
    name = fields.get('up_name') or 'PHP_SESSION_UPLOAD_PROGRESS'
    if name == 'unset': name = 'PHP_SESSION_UPLOAD_PROGRESS'
    sid = 'detectpspbstate%013d' % (os.getpid() % 10**13)   # [0-9a-v] only, 8.3 sid vetting
    B = '----dps'
    prog_field = ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\nps\r\n'
                  '--%s\r\nContent-Disposition: form-data; name="file"; filename="w.bin"\r\n'
                  'Content-Type: application/octet-stream\r\n\r\n' % (B, name, B)).encode()
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
        s.sendall(("POST %s?pubstate=1 HTTP/1.1\r\nHost: x\r\nCookie: PHPSESSID=%s\r\n"
                   "Content-Type: multipart/form-data; boundary=%s\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n"
                   % (path, sid, B, len(body))).encode())
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
        ml('CHAIN|skipped|pubstate POST failed: %s' % e); human('  chain: skipped — plant POST failed'); return None
    rbody = data.decode('utf-8', 'replace').split('\r\n\r\n', 1)[1] if b'\r\n\r\n' in data else ''
    m = re.search(r'PUBSTATE\|cl=(\d+)\|pre=(\d)\|entry=(\S*?)\|sess=(\d+)\|gate=([01])', rbody)
    if not m:
        ml('CHAIN|unknown|no PUBSTATE line: %s' % rbody[:80].replace('\n', ' ')); human('  chain: venue did not answer the plant — see log'); return None
    gate = m.group(5)
    ml('CHAIN-PUBSTATE|gate=%s|entry=%s|pre_start=%s|content_length=%s' % (gate, m.group(3), m.group(2), m.group(1)))
    if gate == '0':
        # Read-back arm: unpatched mod_php hides the parse-window entry from app
        # time, but under cleanup=0 it survives in the session file (WP-oracle
        # pattern). One ~1KB GET on the same sid.
        try:
            st2, rb2, _ = http_req(host, port, '%s?readstate=1' % path,
                                   cookie='PHPSESSID=%s' % sid, timeout=args.timeout, ssl=ssl)
            m2 = re.search(r'READSTATE\|entry=(\S*?)\|sess=\d+\|gate=([01])', rb2)
            if m2:
                ml('CHAIN-READSTATE|gate=%s|entry=%s' % (m2.group(2), m2.group(1)))
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

def write_log(args, host):
    if RAW or not MLINES: return None
    base = args.log or os.path.join(os.getcwd(), 'php2shell-detect-%s.log' % (host or 'local'))
    try:
        with open(base, 'w') as f:
            for l in MLINES:
                f.write(l + '\n')
        return base
    except OSError:
        return None

def main():
    global RAW
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--url', help='live venue: http(s)://host:port/path/detector.php')
    ap.add_argument('--probe', action='store_true', help='run the behavioral probe (HTTP venues)')
    ap.add_argument('--no-chain', action='store_true', help='skip the pubstate chain tier')
    ap.add_argument('--arm-mb', type=float, default=None, help='override probe arm size (MB)')
    ap.add_argument('--arm-cap', type=int, default=48, help='skip probe if computed arm > this MB (default 48)')
    ap.add_argument('--php-bin', default=None, help='php binary for local mode')
    ap.add_argument('--log', default=None, help='detail log path (default ./php2shell-detect-<target>.log)')
    ap.add_argument('--raw', action='store_true', help='machine pipe-format to stdout, no log file')
    ap.add_argument('--color', action='store_true', help='force ANSI color even when piped')
    ap.add_argument('--nocolor', action='store_true', help='disable color (also honors NO_COLOR env)')
    ap.add_argument('--timeout', type=int, default=60)
    args = ap.parse_args()
    RAW = args.raw
    init_color(args, sys.stdout)

    host = port = path = ssl = None
    if args.url:
        got = url_mode(args)
        if got is None: return 4
        fields, host, port, path, ssl = got
    else:
        fields = local_mode(args)
        if fields is None: return 4

    verdict = fields.get('verdict', 'UNKNOWN')
    up_off = fields.get('up_en', '') in ('0', "'0'", 'false', 'False', '')

    psig = None
    if args.probe:
        if not args.url:
            ml('PROBE|not-run|needs --url'); human('  probe: needs --url (rides the live venue parse window)')
        else:
            psig = probe(fields, host, port, path, ssl, args)
    else:
        ml('PROBE|not-run|pass --probe for the behavioral check')

    chain = None
    if not args.no_chain:
        if args.url:
            chain = pubstate(fields, host, port, path, ssl, args)
        else:
            ml('CHAIN|not-run|needs --url')

    # combine: probe outranks lineage (that's the whole point of the probe)
    final, conf = verdict, 'lineage-only'
    if psig == 'FIXED-SIG':   final, conf = 'FIXED', 'probe-confirmed'
    elif psig == 'VULN-SIG':  final, conf = 'VULN', 'probe-confirmed'
    elif psig in ('ARM-MISSED', 'UNKNOWN'): final, conf = 'INCONCLUSIVE', 'probe-armed-but-did-not-fire'
    elif psig == 'SKIPPED':   conf = 'lineage-only (probe skipped)'

    cve_bad = final in ('VULN', 'VULN-EOL')
    armed   = chain == 'ARMED'
    likely  = chain == 'LIKELY'

    ml('DETECT-VERDICT|verdict=%s|static=%s|probe=%s|confidence=%s|chain=%s|php=%s|sapi=%s%s' % (
        final, verdict, psig or 'not-run', conf, chain or 'not-run',
        fields.get('v', '?'), fields.get('sapi', '?'),
        ('|mitigation=door-closed-by-config') if up_off else ''))
    if verdict in ('VULN', 'VULN-EOL'):
        ml('NOTE|lineage verdict is backport-blind: RHEL/Amazon/SRU builds patch without bumping the version — confirm with --probe')

    # ---- human report ----
    target = args.url if args.url else 'local PHP %s (%s)' % (fields.get('v', '?'), fields.get('sapi', '?'))
    if armed and cve_bad:
        vword, vtail = 'VULNERABLE', 'CVE pair unpatched AND our exploit chain is armed'
    elif armed:
        vword, vtail = 'VULNERABLE', 'our exploit chain is armed (vendor CVE pair is patched)'
    elif cve_bad:
        vword, vtail = 'VULNERABLE', 'CVE pair unpatched' + (' — chain likely' if likely else '')
    elif final == 'FIXED' and likely:
        vword, vtail = 'LIKELY', 'CVE pair patched; chain door open but not directly observable (stock cleanup regime)'
    elif final == 'FIXED':
        vword, vtail = 'NOT VULNERABLE', ('upload_progress disables the demonstrated door' if up_off else 'CVE pair patched, chain idle')
    elif final == 'NO-TRIGGER':
        vword, vtail = 'NOT AFFECTED', 'no upload-progress machinery (PHP < 5.4)'
    else:
        vword, vtail = 'INCONCLUSIVE', 'see details below and in the log'
    vw_col = {'VULNERABLE': BRED, 'LIKELY': BYEL, 'NOT VULNERABLE': BGRN,
              'NOT AFFECTED': BGRN, 'INCONCLUSIVE': BCYA}[vword]

    def lab(s):
        return c(s, BOLD)

    def tag(text, col):
        return c('[ %s ]' % text, col)

    print('')
    print('%s %s' % (c('◆ PHP2Shell · CVE-2026-109618/109619', BCYA), c(target, BOLD)))
    print('%s %s' % (lab('  VERDICT  '), c(vword, vw_col) + ' — ' + vtail))
    cve_tag = {'VULN': tag('UNPATCHED', RED), 'VULN-EOL': tag('UNPATCHED · EOL', RED),
               'FIXED': tag('PATCHED', GRN), 'NO-TRIGGER': tag('N/A', GRN),
               'UNKNOWN': tag('UNKNOWN', YEL)}[verdict]
    floor = fields.get('floor', '')
    hum_cve = {'VULN': 'PHP %s predates the fix (floor %s)' % (fields.get('v', '?'), floor),
               'VULN-EOL': 'PHP %s — end-of-life line, never patched in binaries' % fields.get('v', '?'),
               'FIXED': 'PHP %s is at/above the fix%s' % (fields.get('v', '?'), (' (%s)' % floor) if floor else ''),
               'NO-TRIGGER': 'PHP %s predates upload_progress (5.4)' % fields.get('v', '?'),
               'UNKNOWN': 'PHP branch not in the fix table'}
    psig_txt = ('' if psig in (None, 'SKIPPED', 'not-run')
                else ' — probe: %s' % c({'VULN-SIG': 'unpatched behavior', 'FIXED-SIG': 'patched behavior'}.get(psig, 'inconclusive'),
                                        RED if psig == 'VULN-SIG' else GRN if psig == 'FIXED-SIG' else YEL))
    print('%s %s' % (lab('  CVE pair '), cve_tag + ' ' + hum_cve[verdict] + psig_txt))
    hum_chain = {'ARMED': (tag('ARMED', RED), 'the progress entry published live on this venue'),
                 'LIKELY': (tag('LIKELY', YEL), 'door open, but the stock cleanup regime hides the entry from detection'),
                 'IDLE': (tag('IDLE', GRN), 'lever door closed on this venue')}
    if chain:
        ct, cc = hum_chain[chain]
        print('%s %s' % (lab('  Our chain'), ct + ' ' + cc))
    extras = []
    if fields.get('ini') == 'none': extras.append('no php.ini loaded (vendor-strictest defaults)')
    if up_off: extras.append('upload_progress disabled — demonstrated door closed; patch still recommended')
    for e in extras:
        print('  %s' % c('note: ' + e, DIM))

    MLINES.insert(0, 'PHP2SHELL-REPORT|tool=php2shell_detect|cve=CVE-2026-109618,CVE-2026-109619'
                     '|venue=%s|ts=%s' % ((host or 'local'),
                                          datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')))
    logpath = write_log(args, host)
    if logpath:
        print('%s %s' % (lab('  details  '), c(logpath, DIM)))
    elif not RAW and MLINES:
        print('  %s' % c('(could not write the detail log)', DIM))

    if armed or cve_bad: return 2
    if final == 'INCONCLUSIVE': return 3
    if final in ('FIXED', 'NO-TRIGGER'): return 0
    return 3

if __name__ == '__main__':
    sys.exit(main())
