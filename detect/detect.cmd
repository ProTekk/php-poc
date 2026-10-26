@echo off
REM PHP2Shell benign detector (CVE-2026-109618/619) - checks the PHP
REM installed on THIS Windows machine. Needs php.exe on PATH (test: php -v).
REM Exit codes: 0 = fixed/not affected, 2 = vulnerable, 3 = unknown.
REM For a live IIS/Apache venue probe instead:
REM   py -3 detect.py --url http://localhost/php2shell_detect.php --probe
php "%~dp0php2shell_detect.php"
exit /b %ERRORLEVEL%
