<?php
/* cve2 corruption app: the vendor's RCE demos all run in apps that call
 * session_start() (WordPress/Drupal/Joomla); the corruption consumer for the
 * stale BG(unserialize) state is the session-decode at session_start time.
 * App stays dumb: start, report, dump shape. Attacker controls the decoded
 * bytes via the session file (SID is ours). */
session_start();
echo "CVE2-OK sid=" . session_id() . " keys=" . count($_SESSION) . "\n";
foreach ($_SESSION as $k => $v) {
    echo "k:" . $k . " t:" . gettype($v) . "\n";
}
