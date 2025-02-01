#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from bs4 import BeautifulSoup
from time import time
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class XSSHunter:
    def __init__(self, target_url, payload_file):
        self.target_url = unquote(target_url)
        self.payloads = self.load_payloads(payload_file)
        self.headers = self.generate_headers()
        self.injection_points = []
        self.session = self.create_session()
        
    def create_session(self):
        """Create a session with retry logic."""
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def generate_headers(self):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'close'  # Disable Keep-Alive to prevent connection issues
        }

    def load_payloads(self, file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]

    def detect_injection_points(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            if '=' in parsed.path:
                param_part = parsed.path.split('?')[-1] if '?' in parsed.path else parsed.path
                params = parse_qs(param_part)
        
        if not params and 'hotelname=' in self.target_url:
            param_value = self.target_url.split('hotelname=')[1].split('&')[0]
            params = {'hotelname': [param_value]}
        
        self.injection_points = list(params.keys())
        return self.injection_points

    def scan(self):
        vulnerable_params = {}
        total_payloads = len(self.payloads)
        start_time = time()
        xss_found = 0
        
        for param_index, param in enumerate(self.injection_points):
            print(f"\n\033[33m[*] Testing parameter: {param}\033[0m")
            
            for payload_index, payload in enumerate(self.payloads):
                try:
                    parsed = urlparse(self.target_url)
                    query_params = parse_qs(parsed.query)
                    
                    if not query_params and param in parse_qs(parsed.path):
                        path_params = parse_qs(parsed.path)
                        path_params[param] = [payload]
                        new_path = urlencode(path_params, doseq=True).replace('&', '/')
                        target = parsed._replace(path=new_path).geturl()
                    else:
                        query_params[param] = [payload]
                        target = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()
                    
                    response = self.session.get(
                        target,
                        headers=self.headers,
                        allow_redirects=False,
                        timeout=15
                    )
                    
                    if self.check_vulnerability(response, payload):
                        vulnerable_params.setdefault(param, []).append(target)
                        xss_found += 1
                        print(f"  \033[32m[!] XSS FOUND (+1)\033[0m")
                        
                except requests.exceptions.ConnectionError as e:
                    print(f"  \033[31m[Error] Connection Error: {e}\033[0m")
                except requests.exceptions.Timeout as e:
                    print(f"  \033[31m[Error] Timeout Error: {e}\033[0m")
                except Exception as e:
                    print(f"  \033[31m[Error] {str(e)}\033[0m")
                
                finally:
                    elapsed_time = time() - start_time
                    processed = (param_index * total_payloads) + payload_index + 1
                    remaining = total_payloads - payload_index - 1
                    avg_time = elapsed_time / processed if processed > 0 else 0
                    est_minutes = (remaining * avg_time) / 60
                    
                    print(
                        f"  \033[33m[-] Testing payload: {payload[:45]}...\033[0m | "
                        f"\033[36m[±] Payloads left: {remaining}/{total_payloads} | "
                        f"ETA: {est_minutes:.1f}m | "
                        f"XSS FOUND: {xss_found}\033[0m"
                    )
        
        # Save results to results.txt
        with open('results.txt', 'w') as result_file:
            current_date = datetime.now().strftime("%A, %B %d, %Y, %I:%M %p")
            result_file.write(f"XSS Vulnerability Report\nDate: {current_date}\n\n")
            
            if vulnerable_params:
                for param, urls in vulnerable_params.items():
                    result_file.write(f"Parameter: {param}\n")
                    for url in urls:
                        result_file.write(f"  - {url}\n")
                result_file.write("\nTotal XSS vulnerabilities found: {}\n".format(xss_found))
            else:
                result_file.write("No XSS vulnerabilities found.\n")
        
        return vulnerable_params

    def check_vulnerability(self, response, payload):
        """
        Enhanced XSS detection logic.
        """
        decoded_response = unquote(response.text)

        # 1. Check reflection in response body
        if payload in decoded_response:
            return True

        # 2. Check reflection of encoded payload
        encoded_payload = urlencode({'': payload})[1:]
        if encoded_payload in response.text:
            return True

        # 3. Check reflection in HTTP headers
        for header, value in response.headers.items():
            if payload in value or encoded_payload in value:
                return True

        # 4. Check reflection inside <script> tags
        soup = BeautifulSoup(response.text, 'html.parser')
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and (payload in script.string or encoded_payload in script.string):
                return True

        # 5. Check reflection inside HTML attributes
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and (payload in value or encoded_payload in value):
                    return True

        # 6. Check event handler injections
        event_handlers = ['onload', 'onclick', 'onmouseover', 'onerror', 'onsubmit']
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if attr.lower() in event_handlers and (payload in value or encoded_payload in value):
                    return True

        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_url> <payload_file>")
        sys.exit(1)
        
    scanner = XSSHunter(sys.argv[1], sys.argv[2])
    print("\033[33m[+] Detecting injection points...\033[0m")
    injection_points = scanner.detect_injection_points()
    
    if not injection_points:
        print("\033[33m[-] No parameters found - testing URL as-is\033[0m")
        injection_points = ['url']
        
    print(f"\033[33m[+] Starting XSS scan on {len(injection_points)} parameters...\033[0m")
    results = scanner.scan()
    
    if results:
        print("\n\033[32m[!] Vulnerabilities Found:\033[0m")
        for param, urls in results.items():
            print(f"  \033[32mParameter: {param}\033[0m")
            print(f"  \033[32mSuccessful URLs ({len(urls)}):\033[0m")
            for url in urls:
                print(f"    \033[32m- {url}\033[0m")
    else:
        print("\n\033[33m[-] No XSS vulnerabilities found\033[0m")
#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from bs4 import BeautifulSoup
from time import time
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class XSSHunter:
    def __init__(self, target_url, payload_file):
        self.target_url = unquote(target_url)
        self.payloads = self.load_payloads(payload_file)
        self.headers = self.generate_headers()
        self.injection_points = []
        self.session = self.create_session()
        
    def create_session(self):
        """Create a session with retry logic."""
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def generate_headers(self):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'close'  # Disable Keep-Alive to prevent connection issues
        }

    def load_payloads(self, file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]

    def detect_injection_points(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            if '=' in parsed.path:
                param_part = parsed.path.split('?')[-1] if '?' in parsed.path else parsed.path
                params = parse_qs(param_part)
        
        if not params and 'hotelname=' in self.target_url:
            param_value = self.target_url.split('hotelname=')[1].split('&')[0]
            params = {'hotelname': [param_value]}
        
        self.injection_points = list(params.keys())
        return self.injection_points

    def scan(self):
        vulnerable_params = {}
        total_payloads = len(self.payloads)
        start_time = time()
        xss_found = 0
        
        for param_index, param in enumerate(self.injection_points):
            print(f"\n\033[33m[*] Testing parameter: {param}\033[0m")
            
            for payload_index, payload in enumerate(self.payloads):
                try:
                    parsed = urlparse(self.target_url)
                    query_params = parse_qs(parsed.query)
                    
                    if not query_params and param in parse_qs(parsed.path):
                        path_params = parse_qs(parsed.path)
                        path_params[param] = [payload]
                        new_path = urlencode(path_params, doseq=True).replace('&', '/')
                        target = parsed._replace(path=new_path).geturl()
                    else:
                        query_params[param] = [payload]
                        target = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()
                    
                    response = self.session.get(
                        target,
                        headers=self.headers,
                        allow_redirects=False,
                        timeout=15
                    )
                    
                    if self.check_vulnerability(response, payload):
                        vulnerable_params.setdefault(param, []).append(target)
                        xss_found += 1
                        print(f"  \033[32m[!] XSS FOUND (+1)\033[0m")
                        
                except requests.exceptions.ConnectionError as e:
                    print(f"  \033[31m[Error] Connection Error: {e}\033[0m")
                except requests.exceptions.Timeout as e:
                    print(f"  \033[31m[Error] Timeout Error: {e}\033[0m")
                except Exception as e:
                    print(f"  \033[31m[Error] {str(e)}\033[0m")
                
                finally:
                    elapsed_time = time() - start_time
                    processed = (param_index * total_payloads) + payload_index + 1
                    remaining = total_payloads - payload_index - 1
                    avg_time = elapsed_time / processed if processed > 0 else 0
                    est_minutes = (remaining * avg_time) / 60
                    
                    print(
                        f"  \033[33m[-] Testing payload: {payload[:45]}...\033[0m | "
                        f"\033[36m[±] Payloads left: {remaining}/{total_payloads} | "
                        f"ETA: {est_minutes:.1f}m | "
                        f"XSS FOUND: {xss_found}\033[0m"
                    )
        
        # Save results to results.txt
        with open('results.txt', 'w') as result_file:
            current_date = datetime.now().strftime("%A, %B %d, %Y, %I:%M %p")
            result_file.write(f"XSS Vulnerability Report\nDate: {current_date}\n\n")
            
            if vulnerable_params:
                for param, urls in vulnerable_params.items():
                    result_file.write(f"Parameter: {param}\n")
                    for url in urls:
                        result_file.write(f"  - {url}\n")
                result_file.write("\nTotal XSS vulnerabilities found: {}\n".format(xss_found))
            else:
                result_file.write("No XSS vulnerabilities found.\n")
        
        return vulnerable_params

    def check_vulnerability(self, response, payload):
        """
        Enhanced XSS detection logic.
        """
        decoded_response = unquote(response.text)

        # 1. Check reflection in response body
        if payload in decoded_response:
            return True

        # 2. Check reflection of encoded payload
        encoded_payload = urlencode({'': payload})[1:]
        if encoded_payload in response.text:
            return True

        # 3. Check reflection in HTTP headers
        for header, value in response.headers.items():
            if payload in value or encoded_payload in value:
                return True

        # 4. Check reflection inside <script> tags
        soup = BeautifulSoup(response.text, 'html.parser')
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and (payload in script.string or encoded_payload in script.string):
                return True

        # 5. Check reflection inside HTML attributes
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and (payload in value or encoded_payload in value):
                    return True

        # 6. Check event handler injections
        event_handlers = ['onload', 'onclick', 'onmouseover', 'onerror', 'onsubmit']
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if attr.lower() in event_handlers and (payload in value or encoded_payload in value):
                    return True

        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_url> <payload_file>")
        sys.exit(1)
        
    scanner = XSSHunter(sys.argv[1], sys.argv[2])
    print("\033[33m[+] Detecting injection points...\033[0m")
    injection_points = scanner.detect_injection_points()
    
    if not injection_points:
        print("\033[33m[-] No parameters found - testing URL as-is\033[0m")
        injection_points = ['url']
        
    print(f"\033[33m[+] Starting XSS scan on {len(injection_points)} parameters...\033[0m")
    results = scanner.scan()
    
    if results:
        print("\n\033[32m[!] Vulnerabilities Found:\033[0m")
        for param, urls in results.items():
            print(f"  \033[32mParameter: {param}\033[0m")
            print(f"  \033[32mSuccessful URLs ({len(urls)}):\033[0m")
            for url in urls:
                print(f"    \033[32m- {url}\033[0m")
    else:
        print("\n\033[33m[-] No XSS vulnerabilities found\033[0m")
