#!/bin/python3
# iterate thru emails and look for leaks via https://www.hotsheet.com/inoitsu/
# and https://monitor.firefox.com/

import hashlib
import os
import re
import requests
import sys
from requests_toolbelt.multipart.encoder import MultipartEncoder


FFCSRF = "csrfhere"
FFCOOKIE = "connect.sid=xxx; _ga=yyy; _gid=zzz; adUnit=5; _gat=1"


def is_valid_email(email):
    match = re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)
    return bool(match)


def check_at_ff(email):
    url = "https://monitor.firefox.com/scan"
    headers = {
        "Host": "monitor.firefox.com",
        "Cookie": FFCOOKIE,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9"
    }
    emailHash = hashlib.sha1(email.encode('utf-8')).hexdigest()
    data = {
        "_csrf": FFCSRF,
        "pageToken": "",
        "scannedEmailId": 2,
        "email": email,
        "emailHash": emailHash
    }
    response = requests.post(url, headers=headers, data=data)
    if """class="bold">0</span>""" not in response.text:
        with open(str(sys.argv[2]), 'w') as f:
            f.write(f"{email} appeared in a breach. Check {url}\n")


def check_at_hs(email):
    url = "https://www.hotsheet.com/inoitsu/"
    headers = {
        "Host": "www.hotsheet.com",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9"
    }
    encoder = MultipartEncoder(fields={
        "act": email,
        "accounthide": "test",
        "submit": " go "
    })
    headers["Content-Type"] = encoder.content_type
    response = requests.post(url, headers=headers, data=encoder)
    if """BREACH DETECTED!""" in response.text:
        with open(str(sys.argv[2]), 'a') as f:
            f.write(f"{email} appeared in a breach. Check {url}\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("""
Usage:
    python3 icanhazleak.py <IN_FILE> <OUT_FILE>
    - <IN_FILE> must be a newline separated list of email addresses
""")
        os._exit(1)

    with open(str(sys.argv[1]), 'r') as f:
        emails = f.readlines()

    for email in emails:
        email = email.strip()
        if is_valid_email(email):
            check_at_ff(email=email)
            check_at_hs(email=email)
