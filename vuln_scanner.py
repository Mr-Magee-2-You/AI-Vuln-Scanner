import requests

def scan_sqli(url):
    print("Scanning for SQL Injection...")
    payload = "' OR '1'='1"
    try:
        response = requests.get(f"{url}/?id={payload}")
        if "error" in response.text.lower() or "sql" in response.text.lower():
            return True
    except Exception as e:
        print(f"Error scanning SQLi: {e}")
    return False

def scan_xss(url):
    print("Scanning for XSS...")
    payload = "<script>alert('xss')</script>"
    try:
        response = requests.get(f"{url}/?q={payload}")
        if payload in response.text:
            return True
    except Exception as e:
        print(f"Error scanning XSS: {e}")
    return False

def scan_csrf(url):
    print("Scanning for CSRF... (Not implemented)")
    return False

def main():
    target_url = "http://localhost:3001"
    results = []

    print("AI-Powered Vulnerability Scanner")
    print(f"Scanning target URL: {target_url}")

    if scan_sqli(target_url):
        print("[!] SQL Injection vulnerability detected.")
        results.append("SQL Injection: FOUND")
    else:
        results.append("SQL Injection: Not Found")

    if scan_xss(target_url):
        print("[!] XSS vulnerability detected.")
        results.append("XSS: FOUND")
    else:
        results.append("XSS: Not Found")

    if scan_csrf(target_url):
        print("[!] CSRF vulnerability detected.")
        results.append("CSRF: FOUND")
    else:
        results.append("CSRF: Not Found")

    # Save results to file
    with open("scan_results.txt", "w") as f:
        for line in results:
            f.write(f"{line}\n")

    print("Scan complete. Results saved to scan_results.txt.")

if __name__ == "__main__":
    main()
