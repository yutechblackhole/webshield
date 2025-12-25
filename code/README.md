# Vulnerability Scanner for Web Applications

A comprehensive web-based vulnerability scanner that helps identify potential security issues in web applications. Built with Flask backend and a modern web frontend, this tool performs automated security assessments against target URLs.

## 🎯 Features

### Security Checks
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities using common payloads
- **Cross-Site Scripting (XSS)**: Identifies XSS vulnerabilities through payload injection
- **Broken Authentication**: Tests for weak credentials and session management issues
- **Broken Access Control**: Checks for unauthorized access to restricted resources
- **CSRF Protection**: Identifies Cross-Site Request Forgery vulnerabilities
- **Security Misconfiguration**: Detects exposed configuration files (.env, etc.)
- **Sensitive Data Exposure**: Warns about HTTP usage and plaintext data exposure
- **SSRF Vulnerabilities**: Tests for Server-Side Request Forgery issues
- **Cryptographic Failures**: Identifies improperly encrypted sensitive data
- **Remote File Inclusion (RFI)**: Detects RFI vulnerabilities
- **Nikto-style Checks**: 
  - Server header analysis
  - Common file discovery (robots.txt, .git/config, etc.)
  - HTTP method enumeration
  - SSL/TLS certificate validation
  - Directory brute-forcing

### User Interface
- Clean, responsive web interface
- Real-time vulnerability scanning
- Home page with project information
- About page with detailed documentation
- Interactive scanner page with results display

## 📋 Requirements

- Python 3.x
- Flask
- Flask-CORS
- Requests library

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Vulnerability-Scanner-for-Web-Applications
   ```

2. **Install dependencies**
   ```bash
   pip install flask flask-cors requests
   ```

## 🔧 Configuration

No additional configuration is required. The application runs with default settings:
- Flask development server on `localhost:5000`
- CORS enabled for cross-origin requests
- Template folder set to current directory
- Static files served from `static/` folder

## ▶️ Running the Application

1. **Start the Flask server**
   ```bash
   python scanner.py
   ```

2. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`
   - You'll see the home page with scanner options

3. **Run a scan**
   - Navigate to the Scanner page or the Home page
   - Enter the target URL (e.g., `https://example.com`)
   - Click "Start Scan" to begin the vulnerability assessment
   - Review the results for identified vulnerabilities

## 📁 Project Structure

```
├── scanner.py              # Flask backend application
├── index.html              # Home page with scanner form
├── scanner.html            # Scanner results page
├── about.html              # About/documentation page
├── style.css               # Global styles
├── static/
│   └── style.css           # Additional styling
├── Logo/                   # Logo assets
└── README.md               # This file
```

## 🔍 How It Works

### Backend (scanner.py)
The Flask application provides:
- Route handlers for `/`, `/about`, and `/scanner` pages
- `/scan` endpoint for API-based vulnerability scanning
- Modular vulnerability check functions
- Error handling for robustness

### Vulnerability Detection Methods
Each vulnerability type has a dedicated checking function that:
1. Makes HTTP requests to the target URL with test payloads
2. Analyzes the response for indicators of vulnerability
3. Returns findings in a results list
4. Handles errors gracefully without interrupting the scan

### Frontend
- Interactive forms for URL submission
- JavaScript-based AJAX requests to backend
- Real-time result display and formatting
- Responsive design for mobile and desktop

## ⚙️ API Endpoints

### GET `/`
Returns the home page with the scanner interface.

### GET `/about`
Returns the about page with project information.

### GET `/scanner`
Returns the scanner results page.

### POST `/scan`
Performs vulnerability scanning on a target URL.

**Request Body:**
```json
{
  "url": "https://target.com"
}
```

**Response:**
```json
{
  "results": [
    "[+] Vulnerability found...",
    "[-] Check completed...",
    "Server: Apache/2.4.41"
  ]
}
```

## ⚠️ Important Notes

### Legal and Ethical Use
- **Only scan websites you own or have explicit permission to test**
- Unauthorized security scanning of systems you don't own is illegal
- This tool is for educational and authorized penetration testing purposes only
- Always obtain written permission before testing any system

### Limitations
- This is a basic scanner for educational purposes
- Detection methods are signature-based and may have false positives/negatives
- Real-world penetration testing requires more sophisticated tools and manual analysis
- The scanner may not detect all vulnerability types

### Performance
- Scanning may take several seconds depending on target responsiveness
- Timeouts are set to 5 seconds per request
- Multiple requests are made to check various vulnerabilities

## 🛠️ Customization

### Adding Custom Payloads
Edit the payload lists in `scanner.py`:
```python
SQL_PAYLOADS = ['1=1', "' OR '1'='1", "' AND 1=0--"]
XSS_PAYLOADS = ['<script>alert("XSS")</script>', ...]
COMMON_CREDENTIALS = [('admin', 'admin'), ...]
WORDLIST = ["admin", "backup", "config", ...]
```

### Styling
Modify `style.css` and `static/style.css` for custom appearance.

### Adding New Checks
Create new functions following the pattern:
```python
def check_new_vulnerability(url, results):
    try:
        # Your check logic here
        results.append("[+] Vulnerability found!")
    except requests.RequestException as e:
        results.append(f"[-] Error: {str(e)}")
```

## 📊 Sample Output

```
Server: Apache/2.4.41
Found: /robots.txt
Forbidden: /admin/
Not Found: /config.php
Allowed HTTP methods: GET, HEAD, OPTIONS
[+] SQL Injection detected with payload: 1=1
[+] XSS vulnerability detected with payload: <script>alert("XSS")</script>
[+] Security Misconfiguration detected: Exposed .env file
```

## 🐛 Troubleshooting

**Issue: Server won't start**
- Ensure Python 3.x is installed
- Check that all dependencies are installed: `pip install -r requirements.txt`
- Verify port 5000 is not in use

**Issue: CORS errors in browser**
- CORS is enabled by default via Flask-CORS
- Check browser console for detailed error messages

**Issue: Scan times out**
- Target may be unresponsive or blocking requests
- Check your internet connection
- Verify the target URL is correct

**Issue: False positives**
- Some results may be false positives due to signature-based detection
- Manual verification of findings is recommended

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📄 License

This project is provided as-is for educational and authorized testing purposes.

## 👨‍💻 Contributing

Feel free to submit issues and enhancement requests. When contributing:
1. Ensure new features follow the existing code style
2. Add appropriate error handling
3. Update documentation as needed
4. Test thoroughly before submitting

---

**Disclaimer**: This tool should only be used on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.
