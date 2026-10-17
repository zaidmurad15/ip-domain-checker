import os
import re
import argparse
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def is_valid_ip(target):
   
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_pattern, target))

def check_target(target):
    if not API_KEY:
        print("[-] Error: VIRUSTOTAL_API_KEY not found in .env file!")
        return

   
    if is_valid_ip(target):
        target_type = "ip_addresses"
        label = "IP Address"
    else:
        target_type = "domains"
        label = "Domain"

    url = f"https://www.virustotal.com/api/v3/{target_type}/{target}"
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }

    print(f"[*] Scanning {label}: {target} ...")

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            status = data['data']['attributes']['last_analysis_stats']
            
            print(f"\n[+] Scan Results for {label} ({target}):")
            print(f"    - Malicious: {status['malicious']}")
            print(f"    - Harmless:  {status['harmless']}")

        elif response.status_code == 401:
            print("[-] Error 401: Invalid or missing API Key.")
        elif response.status_code == 404:
            print(f"[-] Error 404: {label} not found in VirusTotal database.")
        else:
            print(f"[-] Unexpected Error Code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Command-line IP and Domain Scanner Tool")
    parser.add_argument("target", help="IP address or Domain to scan (e.g., 8.8.8.8 or google.com)")

    args = parser.parse_args()
    check_target(args.target)