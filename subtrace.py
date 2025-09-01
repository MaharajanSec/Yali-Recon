import requests
import re

def fetch_subdomains(domain):
    print(f"Searching for subdomains of {domain} using crt.sh ...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print(" Failed to fetch data from crt.sh")
            return []

        # Extract subdomainsdir
        data = r.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.split("\n"):
                    if "*" not in sub:  # ignore wildcards
                        subdomains.add(sub.strip())

        return sorted(subdomains)

    except Exception as e:
        print(f" Error: {e}")
        return []

def check_alive(subdomains):
    print("\n Checking which subdomains are alive...\n")
    alive = []
    for sub in subdomains:
        url = f"http://{sub}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 400:
                print(f"[+] Alive: {url}")
                alive.append(sub)
        except:
            pass
    return alive

if __name__ == "__main__":
    domain = input("Enter domain (e.g. example.com): ").strip()
    subdomains = fetch_subdomains(domain)

    if subdomains:
        print(f"\n Found {len(subdomains)} subdomains:\n")
        for s in subdomains:
            print(s)

        choice = input("\nDo you want to check which ones are alive? (y/n): ")
        if choice.lower().startswith("y"):
            check_alive(subdomains)
    else:
        print(" No subdomains found.")
