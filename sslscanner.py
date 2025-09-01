import ssl, socket, datetime, pprint

def parse_cert_date(date_str):
    # Try common formats
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None  # if nothing matches

def ssl_scan(host, port=443):
    context = ssl.create_default_context()
    try:
        ip = socket.gethostbyname(host)
        print(f"\n[*] Resolving {host} → {ip}")

        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                # Parse expiry date
                expiry = parse_cert_date(cert['notAfter'])
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                san = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

                print(f"[+] Certificate for {host} ({ip})")
                print(f"    Common Name      : {subject.get('commonName')}")
                print(f"    Alternative DNS  : {san}")
                print(f"    Issuer           : {issuer.get('commonName')}")
                print(f"    Valid From       : {cert['notBefore']}")
                print(f"    Valid Until      : {cert['notAfter']}")
                if expiry:
                    print(f"    Expiry Date      : {expiry}")
                    print(f"    Valid Now        : {expiry > datetime.datetime.utcnow()}")
                print(f"    Serial Number    : {cert.get('serialNumber')}")
                print(f"    Version          : {cert.get('version', 'N/A')}")
                print(f"    Signature Alg    : {cert.get('signatureAlgorithm', 'N/A')}")

                print("\n[*] Full Certificate Dump:")
                pprint.pprint(cert)

    except Exception as e:
        print(f"[-] SSL scan failed for {host}: {e}")

if __name__ == "__main__":
    target = input("Enter domain (e.g. google.com): ").strip()
    ssl_scan(target)
