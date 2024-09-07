import requests
from threading import Thread
from list import *

headers_to_test1 = [
    "Cookie",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Cache-Control"
]
payloads = [
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "badheader"
]

def check_cache_headers(response):
    """Check cache-related headers in the response."""
    cache_headers = {
        'X-Cache': response.headers.get('X-Cache'),
        'Cache-Control': response.headers.get('Cache-Control'),
        'Vary': response.headers.get('Vary'),
        'Age': response.headers.get('Age')
    }
    return cache_headers

def test_header_payload(url, method, header, payload,preheader):
    try:
        if method == 'GET':
            header_pseudo={header: payload}
            update_header = {**preheader, **header_pseudo}
            response = requests.get(url, update_header, timeout=5)
        elif method == 'POST':
            header_pseudo={header: payload}
            update_header = {**preheader, **header_pseudo}
            response = requests.post(url, update_header, timeout=5)  # Adjust data as needed
        else:
            print(f"Unsupported HTTP method: {method}")
            return

        if response.status_code == 200:
            print(f"Testing {method} {header} with payload: {payload}")
            manipulated_response = requests.get(url, headers={header: payload}, timeout=5)
            if manipulated_response.status_code == 200:
                print(f"Response code: {manipulated_response.status_code}")
                print("Checking cache headers...")
                cache_headers = check_cache_headers(manipulated_response)

                if cache_headers.get('X-Cache') == 'hit':
                    print(f"Potential cache poisoning detected with {method} {header} and payload: {payload}")
                    my_list.append(f"Potential cache poisoning detected with {method} {header} and payload: {payload}")
                else:
                    print(f"No cache hit detected for {method} {header} and payload: {payload}")
            else:
                print(f"Failed to get a valid response for {method} {header} with payload: {payload}")
        else:
            print(f"Failed to get a valid response for {method} {header} with payload: {payload}")
    except requests.exceptions.RequestException as e:
        print(f"Request error for {method} {header} with payload {payload}: {e}")

def pseudo_header(url,preheader):
    threads = []
    for header in headers_to_test1:
        for payload in payloads:
            # Test GET request
            thread = Thread(target=test_header_payload, args=(url, 'GET', header, payload,preheader))
            threads.append(thread)
            thread.start()

            # Test POST request
            thread = Thread(target=test_header_payload, args=(url, 'POST', header, payload,preheader))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()