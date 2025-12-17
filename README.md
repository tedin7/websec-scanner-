# WebSec Scanner

A fast, comprehensive web security scanner for finding vulnerabilities in websites.

## Features

- **URL Discovery** - Crawls website to find all internal links
- **Security Header Analysis** - Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- **SSL/TLS Validation** - Certificate expiration, outdated TLS versions
- **Sensitive File Detection** - Scans for exposed `.env`, `.git`, backup files, admin panels
- **CORS Misconfiguration** - Detects dangerous CORS policies
- **Form Security** - Missing CSRF tokens, insecure form actions
- **Cookie Analysis** - Missing Secure, HttpOnly, SameSite flags
- **Information Disclosure** - Exposed emails, internal IPs, stack traces, API keys
- **Technology Fingerprinting** - Detects WordPress, React, Django, Laravel, etc.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/websec-scanner.git
cd websec-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python websec.py example.com

# Fast parallel scan
python websec.py example.com --threads 5 --delay 0.2

# Scan multiple domains
python websec.py example.com api.example.com --threads 4

# Export results to JSON
python websec.py example.com --export-json report.json

# Skip specific checks
python websec.py example.com --skip-ssl --skip-sensitive-files

# Verbose output
python websec.py example.com -v
```

## Options

| Option | Description |
|--------|-------------|
| `--delay` | Delay between requests in seconds (default: 1.0) |
| `--threads` | Number of concurrent threads (default: 1) |
| `--no-vuln-scan` | Disable vulnerability scanning |
| `--skip-ssl` | Skip SSL certificate checks |
| `--skip-sensitive-files` | Skip sensitive file scanning |
| `--export-json FILE` | Export results to JSON file |
| `-v, --verbose` | Enable verbose/debug output |

## Example Output

```
$ python websec.py example.com --threads 4

Scanning website: example.com
============================================================

Step 1: Extracting links from homepage...
Found 45 links to check

Step 2: Scanning homepage for vulnerabilities...
Found 3 potential vulnerabilities on homepage

Step 2b: Running domain-level security checks...
   Checking SSL/TLS certificate... OK
   Checking CORS configuration... OK
   Scanning for exposed sensitive files...
   Found 1 exposed sensitive file!

Step 3: Checking link status and security...
[1/45] https://example.com/about... 200 (2 vulns)
...

Security Vulnerability Summary:
   Critical: 1
   High: 5
   Medium: 12
   Low: 3
   Info: 8
   Total findings: 29
```

## Vulnerability Severity Levels

| Level | Examples |
|-------|----------|
| **Critical** | Exposed API keys, SQL errors, private keys, database connection strings |
| **High** | XSS, CORS origin reflection, missing CSRF, exposed sensitive files |
| **Medium** | Missing security headers, insecure cookies, SSL expiring soon |
| **Low** | Server info disclosure, email exposure, version disclosure |
| **Info** | Technology stack detection |

## Responsible Use

This tool is intended for:
- Security researchers testing their own applications
- Penetration testers with proper authorization
- Developers auditing their own websites
- Bug bounty hunters within program scope

**Always obtain proper authorization before scanning any website you don't own.**

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
