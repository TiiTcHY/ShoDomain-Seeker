import argparse
import requests
import json
import sys

URL = "https://api.shodan.io"
URL_DOMAIN = "https://api.shodan.io/dns/domain/"

class API:
    def __init__(self, key):
        self.api_key = key

    def info_account(self):
        try:
            res = requests.get(f"{URL}/api-info?key={self.api_key}")
            res.raise_for_status()

            data = res.json()
            return data
        except requests.exceptions.RequestException as e:
            raise Exception(f"Something went wrong: {e}")

    def get_subdomain(self, domain):
        try:
            url = f"{URL_DOMAIN}{domain}?key={self.api_key}"
            res = requests.get(url)
            res.raise_for_status()

            data = res.json()
            return data
        except requests.exceptions.RequestException as e:
            raise Exception(f"Something went wrong: {e}")

def print_ascii_art():
    print(r"""
   _____ _           _____                        _          _____           _             
  / ____| |         |  __ \                      (_)        / ____|         | |            
 | (___ | |__   ___ | |  | | ___  _ __ ___   __ _ _ _ __   | (___   ___  ___| | _____ _ __ 
  \___ \| '_ \ / _ \| |  | |/ _ \| '_ ` _ \ / _` | | '_ \   \___ \ / _ \/ _ \ |/ / _ \ '__|
  ____) | | | | (_) | |__| | (_) | | | | | | (_| | | | | |  ____) |  __/  __/   <  __/ |   
 |_____/|_| |_|\___/|_____/ \___/|_| |_| |_|\__,_|_|_| |_| |_____/ \___|\___|_|\_\___|_|   
                                                                                           
    """)

def main():
    print_ascii_art()
    
    parser = argparse.ArgumentParser(description="Find subdomains using Shodan API")
    parser.add_argument("-d", dest="domain", required=True, help="Domain to find subdomains")
    parser.add_argument("-s", dest="shodan_key", required=True, help="Shodan API key")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Show all output")
    parser.add_argument("-o", dest="file_name", help="Save domains into a file")
    args = parser.parse_args()

    if not args.domain or not args.shodan_key:
        print(f"[*] Usage: {sys.argv[0]} -d target.com -s ShodanAPIKey")
        sys.exit(1)

    api = API(args.shodan_key)

    try:
        info = api.info_account()
        print(f"[*] Credits: {info['query_credits']}\nScan Credits: {info['scan_credits']}\n")

        domain_search = args.domain
        subdomain_data = api.get_subdomain(domain_search)

        for v in subdomain_data['data']:
            d = v['subdomain'] + subdomain_data['domain']
            output = f"[*] Domain: {d}\nIP/DNS: {v['value']}\nLast Scan made by Shodan: {v['last_seen']}\n"

            print(output)

            if args.verbose or args.file_name:
                with open(args.file_name, "a") as f:
                    f.write(output + "\n")

        if args.file_name:
            print("[*] DONE writing to file")

    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
