# PHP session.upload_progress — repro & PoC bundle

## Oct 26 update (patched-latest, both SAPIs)

**mod_php:** on the source-built 8.5.12 venue box (Apache 2.4.69 prefork,
tuned ini `cleanup=0`, live WordPress/MediaWiki alongside), `stock_rce.py`
**3/3** — pubstate gate, dial-back shell as `daemon`, banner-verified.

**FPM:** `stock_rce.py` **3/3 on `php:8.5.12-fpm` behind nginx** — official image, *no
php.ini at all*, stock `cleanup=1`: dial-back RCE as `www-data`, `PUBSTATE=1
RC=0`, banner-verified 8.5.12 NTS. The vendor's advisories demonstrated their
exploits on mod_php; **no complete exploit had been demonstrated against FPM** —
as of 2026-10-26, there's one, and it needs neither the OOM spray nor
offsets. The SAPI nuance (in-flight frozen counter `frozen=YES` on patched FPM;
the cross-request abandoned-upload artifact is prefork-native and on FPM wants
`cleanup=0`) and the full receipts: `forensics/fpm-8512-2026-10-26.md`.
Forward paths (distro tail / staleness-as-primitive / next venue):
`forensics/paths-2026-10-26.md`. Staleness report remains **unfiled by owner's
choice** — public repo, open credit.

## Status (Oct 21, 2026)

**Status (Oct 21, 2026).** The two shipped CVEs — **CVE-2026-109618** (RCE via OOM
corruption: allocation failure during request parsing leaves memory half-initialized;
request shutdown reads it) and **CVE-2026-109619** (RCE via stale global state: worker
globals point into freed request memory, consumed by the *next* request) — are vendor
lifetime bugs, both CVSS 9.2. Nothing in this bundle claims to be a weaponized PoC for
them: the CVE driver below is **trigger + patch-signature testing** (what a correct
exploit must pass). The end-to-end exploit chain here rides a **different, adjacent
bug we found**: an uncatalogued upstream *staleness* defect in the upload-progress
counter — reproducible, no CVE, and **surviving the vendor's fix byte-identically**.
Same reachable surface (the pre-RINIT multipart upload-progress window), three
different bugs. Companion reports: *PHP-UAF-writeup.pdf* (summary) and
*PHP-UAF-technical-report.pdf* (mechanisms, paths, evidence ledger).

## Evening update (Oct 21)

`poc/uaf_rce.py` — one-file stdlib CLI, **end-to-end network RCE** on the
adjacent staleness bug: plant → corrupt (frozen `bytes_processed`
signature) → app gates its own progress entry → `system(cmd)` dial-back to
you. Server-side staging: `poc/exploit/app.php` in the docroot, nothing
else — connect-back address and command ride in-band. Venue: Apache
mod_php. (php-fpm's RINIT-before-parse is structurally immune to the
*cross-request consumption* leg specifically — not to the chain's
pubstate gate, which runs on FPM too; see the Oct 26 section above.) Verified
on remote vanilla 8.3.6 mod_php:
**5/5 frozen+shell**, `frozen=1 bytes≈205K/516K`, banner `www-data /
hello-from-uaf / php8.3.6-uaf-revshell-OK`.

`poc/cve2/` — the CVE-only path (no staleness): vendor OOM arm →
published-state gate → dial-back. `rce_run.py` (armed + control),
`rce_shell.py` (playground CLI: `--cmd` inline, typing shell by default,
`--no-arm` control). Caveat kept honest: the CVE-only gate keys on the
harness-observed silent 500 (marker file); engine-level forged dispatch
remains open (0/21 armed trials segfaulted — LIFO self-reclaim hides it).

`poc/uaf_rce.py` v2 modes: default one-shot = **real pty shell** (python3
`pty.spawn` target-side, raw-mode client — Ctrl-C/job control work; auto-
falls back to `--plain` sh -i if python3 absent). `--up FILE` uploads to
`/tmp/uaf_NAME` riding R1's multipart (md5-verified on venue; ceiling =
upload_max_filesize) + `--run` exec. `--serve [F]` runs an attacker-side
http server (embedded `uaf_shell.py` default) so the target downloads and
execs its shell — the initcmd pattern for python-less targets. `--cmd`/
`--n` keep banner mode. Quoting lesson baked in: nothing backslashed may
reach `python -c`'s parser — escapeshellarg passes backslashes literally.

## Requirements

- `php-cli` — unpatched build (tested: distro **8.3.6**, Oct 2026 build; bug reachable
  5.4+). Patched-mode comparison needs your own patched binary via `PHP_BIN=`.
- `python3` (stdlib only), `curl` (forensics only), `setarch` (util-linux), bash.
- Run on loopback; the reverse-shell legs dial back to *this* machine's port.
  No root, no listeners to pre-start — every script binds its own server.

## Layout & quickstart

```
poc/forensics/   run.sh            the frozen-counter repro (~10s)
poc/exploit/     run_exploit.sh    the staleness exploit chain
poc/cve/         cve_driver.py     CVE trigger + patch-signature driver
poc/rung/          rung_driver.py    sinkless dispatch proof (echo-only app)
stock_rce.py     the pubstate staleness chain — stock config, mod_php + FPM venues
php2shell.py     distro-tail census: --wp consumer-app probe mode (paced plant,
                 progress-name cycling, HTTP verdicts); AIO probe+arm+lever
```

```bash
cd poc
bash forensics/run.sh                    # expect: spray line 205318/516112 frozen
bash exploit/run_exploit.sh exploit      # expect: frozen=1, shell: YES (connect-back)
bash exploit/run_exploit.sh interactive  # drops YOU into a shell over the socket
python3 cve/cve_driver.py stock618       # expect: VULN-SIG (silent parse-time bailout)
python3 cve/cve_driver.py stock619       # + sess-file after producer: ABSENT
```

### forensics — the observable bug in one table

Three uploads (small / big / spray) against stock PHP with
`session.upload_progress` on; prints recorded `bytes_processed` vs real POST size.
Small/big self-heal (the allocator hands the freed chunk straight back to the
session re-decode); the spray's 150 fields reclaim it first, and stores through the
dangling bucket pointer stop reaching the live tree → **frozen counter, 10/10 runs**.
No ASAN report and no crash: freed-**and**-reclaimed is sanitizer-legal — which is
why this survived ~20 PHP releases unnoticed.

### exploit — staleness chain (our bug), RCE to interactive shell

Three requests, one session: **R1** plants payload + progress entry, **R2** sprays
(the counter freezes — corruption signature), **R3** *checks the freeze* and only
then fires `system()` in the app phase; connect-back `bash -i` on the socket.
Modes: `sweep | exploit | reliability` (`EXP_N=5` for reliability; interactive mode
uses `RSHELL_TTY`). `TARGET=host:port` exploits a remote harness (connect-back IP
derived automatically; `RHOST=` to pin). Port defaults 18881 / listener 4455
(`EXP_PORT` / `RSHELL_PORT`).

**Honest scope:** the shell dispatches from *app code that observed the corruption
signature* — it proves the observable behavior can drive an execution path (gated
harness execution), not that the staleness defect alone grants arbitrary command
execution on an otherwise unmodified PHP install.

### cve — CVE trigger + patch-signature driver

Vendor trigger shape from the shipped regression test
(`oom_request_parsing_next_request.phpt`): force an OOM during request parsing,
observe this request and the **next** request on the same worker. Signatures
measured on 8.3.6 vs 8.3.36:

| build | producer symptom | session file |
|---|---|---|
| stock 8.3.6 | HTTP 500, **silent** (bailout discards output) | never written |
| patched 8.3.36 | HTTP 200, **visible** delayed-OOM message | written |

Modes: `stock618 stock619 patched618 patched619 remote reliability` (default port
18911; `CVE_PORT`, `N=5`, `ARM_MB` for the OOM arm, `PHP_BIN=` for the patched
binary — the bundle ships stock modes only since patched builds are host-specific).
The `shell leg` is a **gated harness execution check** (payload over connect-back
socket, `RSHELL_LPORT` 4477); no 619-specific *consumer* effect was observed on our
8.3 builds — the vendor's demonstrated 619 producers are 8.4/8.5-era.

### rung — sinkless dispatch proof (2026-10-27)

`probe_app.php` is an **echo-only** app (no `system`/`exec`/`eval`/
`passthru`/`proc_open` sink in its source) that plants int keys plus a
`Probe` object in the session — `__unserialize` and `__destruct` echo
their firing. `rung_driver.py` starts its own `php -S` under `setarch -R`
(harness ini, `RUNG_PORT` 18883), seeds R1, sprays to fire the frozen
counter (R2), decodes and reports (R3); `RUNG_HOST=`/`RUNG_PORT=`/`PATHP=`
drive a remote harness instead.

```console
$ python3 rung/rung_driver.py                   # local harness, seed sweep 1..5
$ FLEN=228 FN=150 python3 rung/rung_driver.py   # spray-shape knobs
```

Verdict: the dispatch legs fire **5/5 on every venue tried** (distro
8.3.6 `php -S` + Apache prefork, patched 8.3.36 vendor venue, 8.5.12
mod_php) — the caller leg needs no execution sink. The freeze itself
reproduces byte-identically on the sinkless app wherever `cleanup=0` +
`min_freq=0` allow the chain; the dangling store landing on app-visible
data is the **open rung** (0/40 on a quiet heap — self-reclaim absorbs
it; placement arithmetic awaits the busy-heap venues).

## Remote harness (for `TARGET=`/`remote`)

One line on the target, single worker, ASLR stilled (this is also the vendor's
demonstrated mod_php posture; on `.170` we verified `www-data` connect-back):

```bash
setarch -R php -S 0.0.0.0:18881 \
  -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 \
  -d session.upload_progress.min_freq=0 -d session.upload_progress.freq=65536 \
  -d session.use_only_cookies=0 -d session.use_strict_mode=0 \
  -d session.save_path=/tmp/sess -d post_max_size=64M exploit/app.php
```

## Caveats worth reading before sharing further

- The staleness bug has **no bug report filed** with the PHP security team —
  by owner's choice, not oversight: the repo went public 2026-10-26 (chain,
  receipts, repro commands all in the open). Whoever wants to file the
  staleness report is welcome to; prior art is this repo's timestamp (first
  commit 2026-10-21, docs drafted 00:07 EDT).
- `memory_limit=-1` mitigates only the **limit-driven** 618 path; other allocation
  failures remain reachable. Updating PHP is the only complete mitigation.
- Patched-version reality: releases for 8.2–8.5; **source-only** backport branches
  for 7.4/8.0/8.1; **nothing upstream** for 5.4–7.3 (distribution/LTS support is a
  separate question).
- CISA KEV: no entry for either CVE as of writing.
