import requests
import re
import concurrent.futures

# Regex for valid domain names
domain_pattern = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

def fetch_subdomains(domain):
    print(f"[*] Searching for subdomains of {domain} using crt.sh ...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print("[-] Failed to fetch data from crt.sh")
            return []

        # crt.sh sometimes returns HTML if rate-limited
        if "application/json" not in r.headers.get("Content-Type", ""):
            print("[-] crt.sh did not return JSON (maybe rate-limited).")
            return []

        data = r.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.split("\n"):
                    sub = sub.strip()
                    if "*" not in sub and domain_pattern.match(sub):
                        subdomains.add(sub)

        return sorted(subdomains)

    except Exception as e:
        print(f"[-] Error: {e}")
        return []


def check_alive(sub):
    """Check if a subdomain is alive (HTTP or HTTPS)."""
    for scheme in ("http://", "https://"):
        url = f"{scheme}{sub}"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code < 400:
                return url
        except requests.RequestException:
            continue
    return None


def run_alive_check(subdomains):
    print("\n[*] Checking which subdomains are alive...\n")
    alive = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_alive, subdomains)

    for result in results:
        if result:
            print(f"[+] Alive: {result}")
            alive.append(result)

    return alive


if __name__ == "__main__":
    domain = input("Enter domain (e.g. example.com): ").strip()
    subdomains = fetch_subdomains(domain)

    if subdomains:
        print(f"\n[+] Found {len(subdomains)} unique subdomains:\n")
        for s in subdomains:
            print(s)

        # Save all subdomains to file
        with open(f"{domain}_subdomains.txt", "w") as f:
            for s in subdomains:
                f.write(s + "\n")
        print(f"\n[+] Saved subdomains to {domain}_subdomains.txt")

        choice = input("\nDo you want to check which ones are alive? (y/n): ")
        if choice.lower().startswith("y"):
            alive = run_alive_check(subdomains)

            # Save alive subdomains
            if alive:
                with open(f"{domain}_alive.txt", "w") as f:
                    for a in alive:
                        f.write(a + "\n")
                print(f"\n[+] Saved alive subdomains to {domain}_alive.txt")
            else:
                print("[-] No alive subdomains found.")
    else:
        print("[-] No subdomains found.")
