# icanhazleak
Simple tool for checking list of emails vs two popular leak/breach databases.

Prerequisites:
1. Visit https://monitor.firefox.com/
2. Note your cookie and csrf values.
3. Fill them in the script as FFCOOKIE and FFCSRF respectively.

Usage: 
    python3 icanhazleak.py <IN_FILE> <OUT_FILE>
    - <IN_FILE> must be a newline separated list of email addresses
