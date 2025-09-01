import socket
import re

def query_whois_server(server, query):
    """Query a WHOIS server and return response"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 43))
    s.send((query + "\r\n").encode("utf-8"))
    
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()
    return response.decode("utf-8", errors="ignore")

def whois(domain):
    # Step 1: Ask IANA which WHOIS server handles this TLD
    tld = domain.split(".")[-1]
    iana_response = query_whois_server("whois.iana.org", tld)
    
    whois_server = None
    for line in iana_response.splitlines():
        if line.lower().startswith("whois:"):
            whois_server = line.split(":")[1].strip()
            break
    
    if not whois_server:
        return f"No WHOIS server found for TLD: .{tld}"
    
    # Step 2: Query the authoritative WHOIS server for the domain
    return query_whois_server(whois_server, domain)

def parse_whois(raw):
    """Extract key fields from WHOIS output"""
    fields = {
        "Registrar": r"Registrar:\s*(.+)",
        "Creation Date": r"Creation Date:\s*(.+)",
        "Expiration Date": r"(?:Expiry Date|Registry Expiry Date):\s*(.+)",
        "Name Servers": r"Name Server:\s*(.+)",
        "Emails": r"[\w\.-]+@[\w\.-]+\.\w+"
    }
    
    parsed = {}
    for key, pattern in fields.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            parsed[key] = list(set([m.strip() for m in matches]))
        else:
            parsed[key] = ["Not found"]
    return parsed

if __name__ == "__main__":
    while True:
        domain = input("\nEnter domain (or 'quit' to exit): ").strip()
        if domain.lower() in ["quit", "exit"]:
            break
        
        raw_data = whois(domain)
        
        if raw_data.startswith("No WHOIS"):
            print(raw_data)
        else:
            print(f"\n🔎 Parsed WHOIS Information for {domain}")
            parsed = parse_whois(raw_data)
            for k, v in parsed.items():
                print(f"{k:15}: {', '.join(v)}")
            
            print("\n📜 Full Raw WHOIS Data")
            print("="*40)
            print(raw_data)
