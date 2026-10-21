import socket, sys
# One-shot loopback listener for the revshell payload. args: host port timeout
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port)); s.listen(1); s.settimeout(timeout)
try:
    c, _ = s.accept()
except socket.timeout:
    sys.exit(3)
c.settimeout(3)
data = b''
try:
    while True:
        chunk = c.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
c.close(); s.close()
sys.stdout.write(data.decode(errors='replace'))
sys.exit(0)
