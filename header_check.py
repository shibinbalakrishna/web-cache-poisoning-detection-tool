import re
import sys
import random
import string
import requests
from threading import Thread
from urllib3.exceptions import InsecureRequestWarning
from list import *


VULNWAR = "qwertyuiop.com"

headers_to_test = {
    "x-forwarded-scheme": "http",
    "x-forwarded-host": VULNWAR,
    "x-forwarded-proto": "http",
    "x-http-method-override": "POST",
    "x-amz-website-redirect-location": VULNWAR,
    "x-rewrite-url": VULNWAR,
    "x-host": VULNWAR,
    "user-agent": VULNWAR,
    "handle": VULNWAR,
    "h0st": VULNWAR,
    "Transfer-Encoding": VULNWAR,
    "x-original-url": VULNWAR,
    "x-original-host": VULNWAR,
    "x-forwarded-prefix": VULNWAR,
    "x-amz-server-side-encryption": VULNWAR,
    "trailer": VULNWAR,
    "fastly-ssl": VULNWAR,
    "fastly-host": VULNWAR,
    "fastly-ff": VULNWAR,
    "fastly-client-ip": VULNWAR,
    "content-type": VULNWAR,
    "api-version": VULNWAR,
    "acunetix-header": VULNWAR,
    "accept-version": VULNWAR
}


payloads = [
    "<script>alert(1)</script>",  # XSS payload
    "../../etc/passwd",           # Path traversal payload
    "badheader"                   # For testing DoS with bad headers
]

def vulnwar_in_response(response):
    for val in response.headers.values():
        if VULNWAR in val:
            return True
    if VULNWAR in response.text:
        return True
    return False

def use_caching(headers):
    return any(headers.get(key) for key in ["X-Cache-Hits", "X-Cache", "Age", "Cf-Cache-Status"]) or ("public" in headers.get("Cache-Control", ""))

def vulnerability_confirmed(responseCandidate, url, randNum, buster):
    try:
        confirmationResponse = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False)
    except:
        return False
    if confirmationResponse.status_code == responseCandidate.status_code and confirmationResponse.text == responseCandidate.text:
        if vulnwar_in_response(responseCandidate):
            return vulnwar_in_response(confirmationResponse)
        return True
    return False

def base_request(url,preheader):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", preheader, allow_redirects=False)
    except:
        return None
    return response

def port_poisoning_check(url, initialResponse):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))

    host = url.split("://")[1].split("/")[0]
    response = None
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers={"Host": f"{host}:8888"}, allow_redirects=False)
    except:
        return
    explicitCache = str(use_caching(response.headers)).upper()

    if response.status_code != initialResponse.status_code:
        print(f"STATUS_CODE difference in {url}. Confirming cache poisoning in progress ...")

        if vulnerability_confirmed(response, url, randNum, buster):
            behavior_or_confirmed_message("CONFIRMED", "STATUS", explicitCache, url)
        else:
            print(f"Unsuccessful vulnerability confirmation on {url}\n")

    elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
        print(f"LENGTH difference in {url}. Confirming cache poisoning in progress ...")
        if vulnerability_confirmed(response, url, randNum, buster):
            behavior_or_confirmed_message("CONFIRMED", "LENGTH", explicitCache, url)
        else:
            print(f"Unsuccessful vulnerability confirmation on {url}\n")
def headers_poisoning_check(url, initialResponse):
    def check_header(header, initialResponse):
        payload = {header: headers_to_test[header]}
        randNum = str(random.randrange(9999999999999))
        buster = str(random.randrange(9999999999999))
        response = None
        try:
            response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers=payload, allow_redirects=False)
        except:
            print(f"Request Error for {url}")
            print("Request error... Skipping the URL.")
            return
        explicitCache = str(use_caching(response.headers)).upper()

        if vulnwar_in_response(response):
            print(f"VULNWAR reflection in {url}. Confirming cache poisoning in progress ...")
            my_list.append(f"VULNWAR reflection in {url}. Confirming cache poisoning in progress ...")
            if vulnerability_confirmed(response, url, randNum, buster):
                behavior_or_confirmed_message("CONFIRMED", explicitCache, url,  header=header)
            else:
                print(f"Unsuccessful vulnerability confirmation on {url}\n")

        elif response.status_code != initialResponse.status_code:
            print(f"STATUS_CODE difference in {url}. Confirming cache poisoning in progress ...")
            if vulnerability_confirmed(response, url, randNum, buster):
                behavior_or_confirmed_message("CONFIRMED", explicitCache, url, header=header)
            else:
                print(f"Unsuccessful vulnerability confirmation on {url}\n")

        elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
            print(f"LENGTH difference in {url}. Confirming cache poisoning in progress ...")
            if vulnerability_confirmed(response, url, randNum, buster):
                behavior_or_confirmed_message("CONFIRMED",  explicitCache, url,header=header,)
            else:
                print(f"Unsuccessful vulnerability confirmation on {url}\n")

    threads = []
    for header in headers_to_test.keys():
        thread = Thread(target=check_header, args=(header, initialResponse))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def cache_poisoning_check(url,preheader):
    initialResponse = base_request(url,preheader)
    if not initialResponse:
        print(f"Request Error for {url}")
        return

    if initialResponse.status_code in (200, 304, 302, 301, 401, 402, 403):
        port_poisoning_check(url, initialResponse)
        headers_poisoning_check(url, initialResponse)

def behavior_or_confirmed_message(behaviorOrConfirmed, explicitCache, url, header="default" ):
    messageDict = {
        "CONFIRMED": "Web Cache Poisoning through HTTP/2 headers is confirmed!" + "  " + f" Via: {header}"
    }

    if header != "default":
        print(messageDict[behaviorOrConfirmed])
        my_list.append(messageDict[behaviorOrConfirmed])
    else:
        print(messageDict[behaviorOrConfirmed])
        my_list.append(messageDict[behaviorOrConfirmed])

