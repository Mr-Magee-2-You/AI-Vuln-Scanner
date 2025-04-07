import requests
import sys

# Save results
def log_result(finding):
    with open("scan_results.txt", "a") as f:
        f.write(finding + "\n")
    print(finding)

# SQL Injection Test
def scan_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}/?id={payload}"
    try:
        response = requests.get(test_url, timeout=10)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            log_result("[SQLi] Potential SQL Injection at: " + test_url)
        else:
            log_result("[SQLi] No SQL Injection vulnerability found at: " + test_url)
    except requests.exceptions.RequestException as e:
        log_result(f"[SQLi] Request failed for {test_url}: {e}")

# XSS Test
def scan_xss(url):
    payload = "<script>alert('xss')</script>"
    test_url = f"{url}/?q={payload}"
    try:
        response = requests.get(test_url, timeout=10)
        if payload in response.text:
            log_result("[XSS] Potential XSS vulnerability at: " + test_url)
        else:
            log_result("[XSS] No XSS vulnerability found at: " + test_url)
    except requests.exceptions.RequestException as e:
        log_result(f"[XSS] Request failed for {test_url}: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1].rstrip('/')
    log_result(f"Scanning target URL: {target_url}")
    scan_sql_injection(target_url)
    scan_xss(target_url)
    log_result("Scan complete. Results saved to scan_results.txt")

if __name__ == "__main__":
    main()
