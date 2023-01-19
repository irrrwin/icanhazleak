#!/bin/python3
# Iterate thru emails and look for leaks via https://www.hotsheet.com/inoitsu/
# and https://monitor.firefox.com/. Project available as is. There are no plans 
# for maintenance or development. No warranty too. Will break if authors modify
# the original html too much. Seriously.

import concurrent.futures
import hashlib
import os
import re
import requests
import sys
from dateutil import parser
from requests_toolbelt.multipart.encoder import MultipartEncoder

from bs4 import BeautifulSoup, Tag



FFCOOKIE = ""
FFCSRF = ""


def is_valid_email(email):
    match = re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)
    return bool(match)


def check_at_ff(email):
    if not is_valid_email(email):
        return
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
    soup = BeautifulSoup(response.text, 'html.parser')
    breach_indicator = soup.select_one('.headline.scan-results-headline span.bold').text
    if breach_indicator != 0:
        breaches = soup.select('.breach-info-wrapper.flx.flx-col div.flx.flx-col')
        for breach in breaches:
            contents = breach.contents
            if "Passwords" in contents[-2].text:
                email = email.ljust(30)
                title = contents[1].text.ljust(30)
                date = parser.parse(contents[5].text)
                date = date.strftime("%Y-%m-%d")
                with open(str(sys.argv[2]), 'a') as f:
                    f.write(f"| {email} | {title} | {date} |\n")


def check_at_hs(email):
    if not is_valid_email(email):
        return
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
    breach_indicator = "BREACH DETECTED!"
    if breach_indicator in response.text:
        soup = BeautifulSoup(response.text, 'html.parser')
        breaches = soup.select_one('div#BreachDtl.hidden-content.phide')
        new_elements = []
        for child in breaches.contents[1:]:
            if child.name is None and child.text == chr(160):
                new_elements.append(Tag(name='breach'))
            else:
                new_elements[-1].append(child)
        for child in new_elements[:-1]:
            contents = child.contents
            if "Passwords" in contents[-2].text:
                email = email.ljust(30)
                title = contents[1].text.ljust(30)
                date = contents[3][-10:]
                with open(str(sys.argv[2]), 'a') as f:
                    f.write(f"| {email} | {title} | {date} |\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("""
Usage:
    python3 icanhazleak.py <IN_FILE> <OUT_FILE>
    - <IN_FILE> must be a newline separated list of email addresses
""")
        os._exit(1)
    elif FFCOOKIE == '' or FFCSRF == '':
        print("""
You must set up your FFCOOKIE and FFCSRF values at the beginning of this script.
""")
        os._exit(1)

    with open(str(sys.argv[1]), 'r') as f:
        emails = f.readlines()
    with open(str(sys.argv[2]), 'w') as f:
        f.write(f"""### Email addresses found in public leaks:
| {'Email address'.ljust(30)} | {'Leak Title'.ljust(30)} | {'Date'.ljust(10)} |
| {'-'*30} | {'-'*30} | {'-'*10} |
""")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = [executor.submit(check_at_ff, email.strip()) for email in emails]
        results += [executor.submit(check_at_hs, email.strip()) for email in emails]
        concurrent.futures.wait(results)
