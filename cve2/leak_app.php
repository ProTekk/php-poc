<?php
/* cve2 leak-leg app: the app never calls session_start().
 * If a PHPSESSID Set-Cookie shows up carrying stale bytes, the disclosure
 * is engine-side (vendor claim: application-agnostic). */
echo "LEAKAPP-OK\n";
