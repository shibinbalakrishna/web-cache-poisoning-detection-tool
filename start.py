
import requests
from threading import Thread
from urllib3.exceptions import InsecureRequestWarning
from header_check import *
from host_check import *
from jsonp import *
from pseudo_headers import *
from query_separator import *
from colorama import Fore, Style, init

from list import *
init()

def main():
            url=input("Enter your test url:")
            print(url)
            if url.startswith('https://') or url.startswith('http://'):
              response = requests.get(url)
              header=response.headers

              if response.status_code < 400:

                pseudo_header(url,header)
                cache_poisoning_check(url,header)
                jsonp(url,header)
                main_param(url)
                hostmain(url,header)
                for item in my_list:
                  print(Fore.CYAN +item+Style.RESET_ALL)
                print("detection compleated")
if __name__ == "__main__":
       main() 