# php2shell_detect — benign client-testing detector for PHP2Shell

One PHP file (+ one Python runner) that answers: **is this target's PHP in
the vulnerable lineage for CVE-2026-109618 / CVE-2026-109619, is the door
config-open, and — when run with `--probe` — does the build actually behave
like a patched one?** No exploit, no writes outside session files, no root,
no external binaries. Runs on Linux, macOS, and Windows.

## The ladder

1. **Version lineage** — `PHP_VERSION` vs the vendor fix floors
   (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
   5.4–8.1 = `VULN-EOL` (in range, source-only backports, no patched binaries
   ever shipped). < 5.4 = `NO-TRIGGER` (no upload_progress).
2. **Config gate** — `session.upload_progress.enabled` (compiled default: ON).
   Off = the demonstrated rfc1867 door is closed by config (patch still required:
   the general-decode refcount class is flag-independent).
3. **Behavioral probe** (`detect.py --probe`) — the vendor's shipped regression
   shape: one oversized form-urlencoded POST forces a parse-phase memory_limit
   fatal. **Unpatched lineage: silent 500 / connection closed mid-upload.
   Patched lineage: 200 + visible "Allowed memory size … exhausted"** (the
   vendor's deferred-OOM symptom). Build-agnostic — this is the check that
   sees through distro backports (RHEL/Amazon/Ubuntu SRU patch without
   bumping the version string, which makes the version tier lie).
4. **Chain tier** (runs by default on `--url`; `--no-chain` to skip) —
   "is this venue vulnerable to *our* exploit, not just the CVEs?" One paced
   ~1.3KB multipart POST carrying the configured progress field, sid in the
   cookie, body dribbled over ~1.35s of flight, then one ~1KB read-back GET
   on the same sid. Verdicts:
   - `chain=ARMED` — the upload-progress entry was observed published in the
     session: the stock-config lever precondition (the window our pubstate
     chain and staleness chain run in) is live on this venue, production
     config, no ini changes. This is the "vulnerable to our exploit" signal.
   - `chain=LIKELY` — `upload_progress` is enabled and the venue accepts the
     plant, but the venue's stock `cleanup=1` regime erases the entry inside
     the parse window (measured behavior on stock builds), so the precondition
     is door-open-but-unobservable. Treated as chain-capable; does not flip
     the exit code by itself.
   - `chain=IDLE` — cleanup=0 regime, every observable chance given, no
     entry: the lever door is honestly closed on this venue.
   Arm-shape pitfalls (measured building this): a sub-second upload publishes
   nothing (`min_freq` default is 1 **second**), and the stock rfc1867 path
   only engages on a **known Content-Length** — chunked POSTs don't open the
   door on unpatched builds. So: paced, Content-Length, ~1.35s.

The probe outranks the version tier whenever they disagree; the final
`DETECT-VERDICT` line says which one confirmed.

**Exit codes** (runner and CLI detector agree): 0 no findings, 2 vulnerable —
CVE-lineage VULN **or** chain ARMED, 3 inconclusive/unknown, 4
unreachable/bad usage. So a fully CVE-patched box running our chain (e.g.
8.5.12 with cleanup=0) exits 2 on the chain signal alone — that's the
"vulnerable to our exploit too" contract.

## Usage

    # check the PHP on this box (CLI) — exit code IS the verdict
    php poc/detect/php2shell_detect.php          # machine line, exit code verdict
    python3 poc/detect/detect.py                 # human report + detail log

    # check a live web venue: deploy the .php to a docroot, then
    python3 poc/detect/detect.py --url http://host[:port]/php2shell_detect.php --probe

The runner prints a short human report (RESULT headline + two or three plain
lines) and writes every machine-parseable pipe-format line to a detail log
(`./php2shell-detect-<target>.log`, override with `--log`, or use `--raw` to
get the pipe lines on stdout with no log — that's the legacy scripting mode).

## Windows

- **CLI:** `detect.cmd` (needs `php` on PATH). Exit code → `%ERRORLEVEL%`.
- **Live venue (IIS or Apache):** drop `php2shell_detect.php` into the site
  root, then `py -3 detect.py --url http://localhost/php2shell_detect.php --probe`.
  No POSIX deps anywhere in either file (no pcntl/posix, no shelling out).
- PHP on IIS is typically ZTS (`php8ts.dll`, FastCGI or ISAPI): the detector
  reports `zts=1` and `sapi=…`. Per-worker staleness semantics are identical
  (globals are per-thread/per-process either way).
- **Probe honesty on Windows/FastCGI:** a bailout may end the FastCGI worker
  (`php-cgi.exe` respawn) — the canary line reports `pid_before ≠ pid_after`
  as a benign, vuln-consistent churn note. Windows version checks are *more*
  trustworthy than Linux ones (php.net/Zend builds carry no silent backport
  patching), so lineage-only mode is a fair default there.

## Probe benignity budget

- One POST body ≈ 1.5× the venue's `memory_limit` (+1MB), default cap 48MB
  (`--arm-cap`). One request; worst case a worker bounce on FPM/cgi.
- Skips honestly and says why: `memory_limit=-1` (unbounded arm isn't
  benign) or `post_max_size` below the limit (truncation neuters the arm —
  raising it is a config change, not a probe).
- Canary requests are ~1KB. Session files land in the venue's save_path only.

## Verified venues (2026-10-26)

| venue | PHP | static | probe | chain | final |
|---|---|---|---|---|---|
| local CLI (Ubuntu 24.04 stock) | 8.3.6 | VULN | n/a | n/a | VULN (exit 2) |
| local CLI (source build) | 8.3.36 | FIXED | n/a | n/a | FIXED (exit 0) |
| local CLI (source build) | 8.5.12 | FIXED | n/a | n/a | FIXED (exit 0) |
| bench php -S, 8M limit | 8.3.6 | VULN | silent 500 = VULN-SIG | LIKELY (cleanup=1) | VULN probe-confirmed |
| bench php -S, 8M limit | 8.3.36 | FIXED | 200+exhausted = FIXED-SIG | LIKELY (cleanup=1) | FIXED probe-confirmed |
| .170 Apache prefork :18990 | 8.3.6 SRU | VULN | silent 500, worker stable | LIKELY (cleanup=1) | VULN probe-confirmed |
| .16 Apache prefork (src-build) | 8.5.12 | FIXED | skipped (post 8M < mem 128M) | **ARMED** (cleanup=0, entry observed) | chain finding, exit 2 |

Windows itself was not a test venue this round (no Windows box on the LAN) —
support there is by construction (no POSIX deps, exit-code contract, IIS
notes above) plus one measured pitfall fixed: `PHP_ZTS` is defined on NTS
builds too; its *value* is the thread-safety flag.

## Scope note

The CVE tiers detect the **CVE pair's lineage**; the chain tier detects
whether **our lever's precondition** is live on the venue's production config.
They answer different questions and both belong in the client report: a
vendor-patched box can be (and our .16 is) chain-capable — the uncatalogued
frozen-counter staleness survives the vendor fix byte-identically on
8.3.36/8.5.12. Frozen-counter *forensics* additionally want cleanup=0; the
chain tier flags when the venue's cleanup regime makes the entry unobservable
(LIKELY) instead of pretending the door is shut.
