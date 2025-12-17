#!/usr/bin/env python3
"""
Security URL Checker - Comprehensive URL and vulnerability scanner
Usage: python security_url_checker.py <domain1> <domain2> ...
"""

import requests
import re
import sys
import time
import ssl
import socket
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
import argparse
import logging
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class SecurityURLChecker:
    def __init__(self, delay=1.0, check_vulnerabilities=True, threads=1,
                 skip_ssl=False, skip_sensitive_files=False):
        self.delay = delay
        self.check_vulnerabilities = check_vulnerabilities
        self.threads = threads
        self.skip_ssl = skip_ssl
        self.skip_sensitive_files = skip_sensitive_files
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)

    def extract_links_from_page(self, url):
        """Extract links from a single page"""
        try:
            self.logger.info(f"Fetching: {url}")
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                self.logger.warning(f"Failed to fetch {url}: {response.status_code}")
                return set(), None

            # Extract href and src attributes
            all_links = set()

            # Find href attributes
            hrefs = re.findall(
                r'href=["\']([^"\']+)["\']', response.text, re.IGNORECASE
            )
            # Find src attributes
            srcs = re.findall(r'src=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            # Find action attributes in forms
            actions = re.findall(
                r'action=["\']([^"\']+)["\']', response.text, re.IGNORECASE
            )

            all_links.update(hrefs)
            all_links.update(srcs)
            all_links.update(actions)

            # Clean and convert to absolute URLs
            cleaned = set()
            parsed_base = urlparse(url)

            for link in all_links:
                # Skip special protocols and fragments
                if link.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                    continue

                # Convert to absolute URL
                absolute = urljoin(url, link)
                parsed_link = urlparse(absolute)

                # Only keep same domain URLs and HTTP/HTTPS
                if parsed_link.netloc == parsed_base.netloc and parsed_link.scheme in (
                    "http",
                    "https",
                ):
                    cleaned.add(absolute.split("#")[0])  # Remove fragment

            self.logger.info(f"Found {len(cleaned)} links on {url}")
            return cleaned, response

        except Exception as e:
            self.logger.error(f"Error extracting links from {url}: {e}")
            return set(), None

    def check_url_security(self, url, response=None):
        """Check URL for security vulnerabilities"""
        vulnerabilities = []

        # Use existing response if available, otherwise fetch
        if response is None:
            try:
                response = self.session.get(url, timeout=10)
            except Exception as e:
                return [{"type": "connection_error", "url": url, "error": str(e)}]

        try:
            content = response.text.lower()
            headers = response.headers

            # Check for common vulnerabilities (refined patterns to reduce false positives)
            vuln_checks = [
                # SQL Injection patterns - look for actual SQL in error messages or URLs
                (
                    r"(sql\s*syntax|mysql_fetch|pg_query|sqlite_|ORA-\d{5}|SQL\s*Server.*?error|unclosed quotation mark)",
                    "sql_error_disclosure",
                ),
                # XSS - only flag inline event handlers in user content areas, not in scripts
                (
                    r"(<script[^>]*>(?:document\.cookie|eval\(|alert\(|window\.location)[^<]*</script>)",
                    "potential_xss_injection",
                ),
                # Directory traversal - actual path traversal in URLs/params
                (
                    r"(\/etc\/passwd|\/etc\/shadow|\/windows\/system32|\.\.\/\.\.\/|proc\/self\/environ)",
                    "potential_directory_traversal",
                ),
                # Debug/error information disclosure
                (
                    r"(Fatal error:|Parse error:|Warning:|Notice:|stack\s*trace:|Traceback \(most recent|Exception in thread)",
                    "error_disclosure",
                ),
                # Hardcoded credentials in HTML (not JS variables)
                (
                    r"(password\s*[=:]\s*[\"'][^\"']{4,}[\"']|api[_-]?key\s*[=:]\s*[\"'][a-zA-Z0-9]{16,}[\"'])",
                    "hardcoded_credentials",
                ),
                # Database connection strings
                (
                    r"(mongodb://|mysql://|postgres://|redis://)[^\s\"'<>]+",
                    "exposed_connection_string",
                ),
                # Private keys
                (
                    r"(-----BEGIN\s*(RSA\s*)?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----)",
                    "exposed_private_key",
                ),
            ]

            for pattern, vuln_type in vuln_checks:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append(
                        {
                            "type": vuln_type,
                            "url": url,
                            "matches": len(matches),
                            "severity": self._get_severity(vuln_type),
                        }
                    )

            # Check HTTP headers for security issues
            header_vulns = self._check_headers(headers, url)
            vulnerabilities.extend(header_vulns)

            # Check for outdated software
            software_vulns = self._check_software_info(headers, content, url)
            vulnerabilities.extend(software_vulns)

            # Check cookie security
            cookie_vulns = self._check_cookies(response, url)
            vulnerabilities.extend(cookie_vulns)

            # Check for form security issues
            form_vulns = self._check_forms(content, url)
            vulnerabilities.extend(form_vulns)

            # Check for information disclosure
            info_vulns = self._check_information_disclosure(content, headers, url)
            vulnerabilities.extend(info_vulns)

            # Check for open redirects
            redirect_vulns = self._check_open_redirects(url, response)
            vulnerabilities.extend(redirect_vulns)

            # Technology fingerprinting
            tech_vulns = self._fingerprint_technology(content, headers, url)
            vulnerabilities.extend(tech_vulns)

        except Exception as e:
            vulnerabilities.append(
                {"type": "scan_error", "url": url, "error": str(e), "severity": "low"}
            )

        return vulnerabilities

    def _get_severity(self, vuln_type):
        """Determine severity level for vulnerability type"""
        severity_map = {
            # Critical
            "sql_error_disclosure": "critical",
            "exposed_connection_string": "critical",
            "exposed_private_key": "critical",
            "hardcoded_credentials": "critical",
            "api_key_exposure": "critical",
            "cors_wildcard_with_credentials": "critical",
            "ssl_certificate_expired": "critical",
            "sensitive_file_exposed": "critical",
            # High
            "potential_xss_injection": "high",
            "potential_directory_traversal": "high",
            "cors_origin_reflection": "high",
            "outdated_tls_version": "high",
            "ssl_error": "high",
            "form_security_issues": "high",
            "open_redirect": "high",
            "error_disclosure": "high",
            # Medium
            "missing_security_headers": "medium",
            "insecure_cookie": "medium",
            "cors_null_origin": "medium",
            "ssl_certificate_expiring_soon": "medium",
            "stack_trace_exposure": "medium",
            # Low
            "connection_error": "low",
            "server_info_disclosure": "low",
            "wordpress_version_disclosure": "low",
            "email_disclosure": "low",
            "internal_ip_disclosure": "low",
            # Info
            "technology_detected": "info",
        }
        return severity_map.get(vuln_type, "medium")

    def _check_headers(self, headers, url):
        """Check HTTP headers for security issues"""
        vulnerabilities = []

        # Missing security headers
        security_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-XSS-Protection": "XSS protection",
            "X-Content-Type-Options": "MIME type sniffing protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "Content-Security-Policy": "Content Security Policy",
            "Referrer-Policy": "Referrer policy",
        }

        missing_headers = []
        for header, description in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)

        if missing_headers:
            vulnerabilities.append(
                {
                    "type": "missing_security_headers",
                    "url": url,
                    "missing_headers": missing_headers,
                    "severity": "medium",
                }
            )

        # Check for server information disclosure
        if "Server" in headers:
            server_info = headers["Server"]
            if any(
                software in server_info.lower()
                for software in ["apache", "nginx", "iis", "php", "asp.net"]
            ):
                vulnerabilities.append(
                    {
                        "type": "server_info_disclosure",
                        "url": url,
                        "server": server_info,
                        "severity": "low",
                    }
                )

        return vulnerabilities

    def _check_software_info(self, headers, content, url):
        """Check for outdated software information"""
        vulnerabilities = []

        # Check for WordPress version in meta tags or headers
        wp_version_patterns = [
            r"wp-content/themes/[^/]+/style\.css\?ver=(\d+\.\d+\.\d+)",
            r"wp-includes/js/jquery/jquery\.js\?ver=(\d+\.\d+\.\d+)",
            r'generator".*?wordpress (\d+\.\d+\.\d+)',
        ]

        for pattern in wp_version_patterns:
            match = re.search(pattern, content)
            if match:
                version = match.group(1)
                vulnerabilities.append(
                    {
                        "type": "wordpress_version_disclosure",
                        "url": url,
                        "version": version,
                        "severity": "low",
                    }
                )
                break

        return vulnerabilities

    def _check_cookies(self, response, url):
        """Check cookies for security flags"""
        vulnerabilities = []

        cookies = response.cookies
        for cookie in cookies:
            issues = []

            # Check for missing Secure flag on HTTPS
            if url.startswith('https://') and not cookie.secure:
                issues.append('missing Secure flag')

            # Check for missing HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
                # requests doesn't expose HttpOnly directly, check raw header
                set_cookie = response.headers.get('Set-Cookie', '')
                if cookie.name in set_cookie and 'httponly' not in set_cookie.lower():
                    issues.append('missing HttpOnly flag')

            # Check for missing SameSite attribute
            if not cookie.has_nonstandard_attr('SameSite'):
                set_cookie = response.headers.get('Set-Cookie', '')
                if cookie.name in set_cookie and 'samesite' not in set_cookie.lower():
                    issues.append('missing SameSite attribute')

            if issues:
                vulnerabilities.append({
                    'type': 'insecure_cookie',
                    'url': url,
                    'cookie_name': cookie.name,
                    'issues': issues,
                    'severity': 'medium' if 'Secure' in str(issues) else 'low'
                })

        return vulnerabilities

    def _check_cors(self, url):
        """Check for CORS misconfigurations"""
        vulnerabilities = []

        try:
            # Test with a malicious origin
            test_origins = [
                'https://evil.com',
                'https://attacker.com',
                'null'
            ]

            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10)

                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')

                # Check for wildcard with credentials
                if acao == '*' and acac.lower() == 'true':
                    vulnerabilities.append({
                        'type': 'cors_wildcard_with_credentials',
                        'url': url,
                        'severity': 'critical',
                        'details': 'Wildcard origin with credentials allowed'
                    })
                    break

                # Check if arbitrary origin is reflected
                if acao == origin and origin != 'null':
                    vulnerabilities.append({
                        'type': 'cors_origin_reflection',
                        'url': url,
                        'reflected_origin': origin,
                        'severity': 'high',
                        'details': 'Server reflects arbitrary Origin header'
                    })
                    break

                # Check for null origin allowed
                if acao == 'null':
                    vulnerabilities.append({
                        'type': 'cors_null_origin',
                        'url': url,
                        'severity': 'medium',
                        'details': 'Null origin is allowed (sandboxed iframe attacks)'
                    })
                    break

        except Exception as e:
            self.logger.debug(f"CORS check error for {url}: {e}")

        return vulnerabilities

    def _check_ssl_certificate(self, domain):
        """Check SSL/TLS certificate for issues"""
        vulnerabilities = []

        try:
            parsed = urlparse(domain if '://' in domain else f'https://{domain}')
            hostname = parsed.netloc or parsed.path

            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days

                    if days_until_expiry < 0:
                        vulnerabilities.append({
                            'type': 'ssl_certificate_expired',
                            'url': f'https://{hostname}',
                            'expired_date': cert['notAfter'],
                            'severity': 'critical'
                        })
                    elif days_until_expiry < 30:
                        vulnerabilities.append({
                            'type': 'ssl_certificate_expiring_soon',
                            'url': f'https://{hostname}',
                            'expires_in_days': days_until_expiry,
                            'severity': 'medium'
                        })

                    # Check for weak signature algorithm
                    # Note: Modern Python/OpenSSL should reject truly weak certs

                    # Get TLS version
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        vulnerabilities.append({
                            'type': 'outdated_tls_version',
                            'url': f'https://{hostname}',
                            'tls_version': tls_version,
                            'severity': 'high'
                        })

        except ssl.SSLError as e:
            vulnerabilities.append({
                'type': 'ssl_error',
                'url': domain,
                'error': str(e),
                'severity': 'high'
            })
        except Exception as e:
            self.logger.debug(f"SSL check error for {domain}: {e}")

        return vulnerabilities

    def _check_sensitive_files(self, base_url):
        """Check for exposed sensitive files and directories"""
        vulnerabilities = []

        sensitive_paths = [
            # Configuration files
            ('/.env', 'Environment configuration file'),
            ('/.git/config', 'Git configuration (repository exposure)'),
            ('/.git/HEAD', 'Git HEAD file (repository exposure)'),
            ('/.svn/entries', 'SVN entries (repository exposure)'),
            ('/.htaccess', 'Apache configuration file'),
            ('/.htpasswd', 'Apache password file'),
            ('/web.config', 'IIS configuration file'),
            ('/config.php', 'PHP configuration file'),
            ('/config.yml', 'YAML configuration file'),
            ('/config.json', 'JSON configuration file'),
            ('/settings.py', 'Python settings file'),

            # Backup files
            ('/backup.sql', 'SQL backup file'),
            ('/database.sql', 'Database dump'),
            ('/dump.sql', 'Database dump'),
            ('/backup.zip', 'Backup archive'),
            ('/backup.tar.gz', 'Backup archive'),

            # Debug/Admin endpoints
            ('/phpinfo.php', 'PHP info page'),
            ('/info.php', 'PHP info page'),
            ('/server-status', 'Apache server status'),
            ('/server-info', 'Apache server info'),
            ('/.DS_Store', 'MacOS directory metadata'),
            ('/debug', 'Debug endpoint'),
            ('/admin', 'Admin panel'),
            ('/wp-admin', 'WordPress admin'),
            ('/administrator', 'Admin panel'),

            # API documentation
            ('/swagger.json', 'Swagger API documentation'),
            ('/api-docs', 'API documentation'),
            ('/graphql', 'GraphQL endpoint'),
            ('/.well-known/security.txt', 'Security policy file'),

            # Log files
            ('/error.log', 'Error log file'),
            ('/access.log', 'Access log file'),
            ('/debug.log', 'Debug log file'),
        ]

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path, description in sensitive_paths:
            try:
                test_url = base + path
                response = self.session.get(test_url, timeout=5, allow_redirects=False)

                # Check for successful response (not 404/403)
                if response.status_code == 200:
                    # Verify it's not just a generic page
                    content_length = len(response.content)
                    if content_length > 0:
                        # Additional checks for specific files
                        is_sensitive = False

                        if '.git' in path:
                            if 'ref:' in response.text or '[core]' in response.text:
                                is_sensitive = True
                        elif '.env' in path:
                            if '=' in response.text and len(response.text) < 50000:
                                is_sensitive = True
                        elif path.endswith('.sql'):
                            if 'CREATE TABLE' in response.text or 'INSERT INTO' in response.text:
                                is_sensitive = True
                        elif 'phpinfo' in path or 'info.php' in path:
                            if 'PHP Version' in response.text:
                                is_sensitive = True
                        elif 'swagger' in path.lower():
                            if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                                is_sensitive = True
                        else:
                            # Generic check - file exists and has content
                            is_sensitive = True

                        if is_sensitive:
                            severity = 'critical' if any(x in path for x in ['.env', '.git', '.sql', 'passwd', 'config']) else 'high'
                            vulnerabilities.append({
                                'type': 'sensitive_file_exposed',
                                'url': test_url,
                                'description': description,
                                'severity': severity,
                                'content_length': content_length
                            })

            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")
                continue

            time.sleep(0.1)  # Rate limiting

        return vulnerabilities

    def _check_forms(self, content, url):
        """Analyze forms for security issues"""
        vulnerabilities = []

        # Find all forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.IGNORECASE | re.DOTALL)

        for i, form in enumerate(forms):
            form_issues = []

            # Check for CSRF token
            has_csrf = bool(re.search(
                r'(csrf|_token|authenticity_token|__RequestVerificationToken)',
                form, re.IGNORECASE
            ))

            if not has_csrf:
                form_issues.append('missing CSRF token')

            # Check for password fields without autocomplete="off"
            password_fields = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', form, re.IGNORECASE)
            for pf in password_fields:
                if 'autocomplete' not in pf.lower() or 'autocomplete="off"' not in pf.lower():
                    form_issues.append('password field allows autocomplete')
                    break

            # Check for action URL
            action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
            if action_match:
                action = action_match.group(1)
                # Check if form posts to HTTP on HTTPS page
                if url.startswith('https://') and action.startswith('http://'):
                    form_issues.append('form posts to insecure HTTP endpoint')

            # Check for method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()
                # GET method with sensitive fields
                if method == 'GET' and password_fields:
                    form_issues.append('sensitive data submitted via GET method')

            if form_issues:
                vulnerabilities.append({
                    'type': 'form_security_issues',
                    'url': url,
                    'form_index': i + 1,
                    'issues': form_issues,
                    'severity': 'high' if 'CSRF' in str(form_issues) else 'medium'
                })

        return vulnerabilities

    def _check_open_redirects(self, url, response):
        """Check for potential open redirect vulnerabilities"""
        vulnerabilities = []

        # Check URL parameters for redirect indicators
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'returnTo',
                          'goto', 'dest', 'destination', 'redir', 'redirect_uri', 'continue']

        for param in redirect_params:
            if param in params or param.lower() in [p.lower() for p in params]:
                # Found a redirect parameter - test it
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, f'{param}=https://evil.com', parsed.fragment
                ))

                try:
                    test_response = self.session.get(test_url, timeout=10, allow_redirects=False)

                    # Check if it redirects to our evil URL
                    location = test_response.headers.get('Location', '')
                    if 'evil.com' in location:
                        vulnerabilities.append({
                            'type': 'open_redirect',
                            'url': url,
                            'parameter': param,
                            'severity': 'medium',
                            'details': f'Parameter {param} allows arbitrary redirect'
                        })
                except Exception as e:
                    self.logger.debug(f"Open redirect check error: {e}")

        return vulnerabilities

    def _check_information_disclosure(self, content, headers, url):
        """Check for information disclosure in responses"""
        vulnerabilities = []

        # Check for exposed email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
        if emails:
            unique_emails = list(set(emails))[:5]  # Limit to 5
            vulnerabilities.append({
                'type': 'email_disclosure',
                'url': url,
                'emails': unique_emails,
                'severity': 'low'
            })

        # Check for internal IP addresses
        internal_ips = re.findall(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            content
        )
        if internal_ips:
            vulnerabilities.append({
                'type': 'internal_ip_disclosure',
                'url': url,
                'ips': list(set(internal_ips))[:5],
                'severity': 'low'
            })

        # Check for stack traces
        stack_trace_patterns = [
            r'at\s+[\w.]+\([\w]+\.java:\d+\)',  # Java
            r'File\s+"[^"]+",\s+line\s+\d+',     # Python
            r'at\s+[\w\\/.]+\.php:\d+',          # PHP
            r'at\s+[\w.]+\s+\([^)]+:\d+:\d+\)',  # JavaScript/Node
        ]

        for pattern in stack_trace_patterns:
            if re.search(pattern, content):
                vulnerabilities.append({
                    'type': 'stack_trace_exposure',
                    'url': url,
                    'severity': 'medium',
                    'details': 'Application stack trace found in response'
                })
                break

        # Check for API keys and secrets (specific patterns to reduce false positives)
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'ASIA[0-9A-Z]{16}', 'AWS Temporary Access Key'),
            (r'(?:sk|pk)_live_[0-9a-zA-Z]{24,}', 'Stripe API Key'),
            (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token'),
            (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token'),
            (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'ya29\.[0-9A-Za-z\-_]+', 'Google OAuth Token'),
        ]

        for pattern, key_type in secret_patterns:
            matches = re.findall(pattern, content)
            if matches:
                vulnerabilities.append({
                    'type': 'api_key_exposure',
                    'url': url,
                    'key_type': key_type,
                    'count': len(matches),
                    'severity': 'critical'
                })
                break

        return vulnerabilities

    def _fingerprint_technology(self, content, headers, url):
        """Enhanced technology fingerprinting"""
        vulnerabilities = []
        detected_tech = []

        # Framework detection patterns
        frameworks = [
            (r'wp-content|wp-includes', 'WordPress'),
            (r'drupal|sites/default|sites/all', 'Drupal'),
            (r'joomla|/administrator/|com_content', 'Joomla'),
            (r'laravel|laravel_session', 'Laravel'),
            (r'django|csrfmiddlewaretoken', 'Django'),
            (r'rails|action_controller|_rails', 'Ruby on Rails'),
            (r'express|connect\.sid', 'Express.js'),
            (r'next\.js|__next|_next', 'Next.js'),
            (r'react|reactroot|__react', 'React'),
            (r'angular|ng-version|ng-app', 'Angular'),
            (r'vue\.js|v-cloak|vue-router', 'Vue.js'),
            (r'shopify|cdn\.shopify', 'Shopify'),
            (r'wix\.com|wixstatic', 'Wix'),
            (r'squarespace|sqsp', 'Squarespace'),
        ]

        for pattern, tech in frameworks:
            if re.search(pattern, content, re.IGNORECASE):
                detected_tech.append(tech)

        # Check headers for technology info
        header_tech = {
            'X-Powered-By': None,
            'X-AspNet-Version': 'ASP.NET',
            'X-Generator': None,
            'X-Drupal-Cache': 'Drupal',
            'X-Drupal-Dynamic-Cache': 'Drupal',
        }

        for header, tech_name in header_tech.items():
            if header in headers:
                value = headers[header]
                detected_tech.append(tech_name or value)

        if detected_tech:
            vulnerabilities.append({
                'type': 'technology_detected',
                'url': url,
                'technologies': list(set(detected_tech)),
                'severity': 'info'
            })

        return vulnerabilities

    def check_url(self, url):
        """Check a single URL status and security"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            vulnerabilities = []

            # Only scan for vulnerabilities if we're still on the same domain
            # (avoid scanning external sites after redirects)
            original_domain = urlparse(url).netloc
            final_domain = urlparse(response.url).netloc

            if self.check_vulnerabilities:
                if original_domain == final_domain:
                    vulnerabilities = self.check_url_security(url, response)
                else:
                    # External redirect - don't scan the external site
                    self.logger.debug(f"Skipping vuln scan - redirected to external: {response.url}")

            return url, response.status_code, None, vulnerabilities
        except Exception as e:
            return url, None, str(e), []

    def scan_website(self, domain):
        """Scan a website for 404 errors and vulnerabilities"""
        if not domain.startswith(("http://", "https://")):
            url = f"https://{domain}"
        else:
            url = domain

        print(f"\n🔍 Scanning website: {domain}")
        print("=" * 60)

        # Step 1: Get all links from homepage
        print("\n📋 Step 1: Extracting links from homepage...")
        links, homepage_response = self.extract_links_from_page(url)

        if not links:
            print("❌ No links found on homepage")
            return {}, {}

        print(f"✅ Found {len(links)} links to check")

        # Step 2: Check homepage for vulnerabilities first
        all_vulnerabilities = []
        if self.check_vulnerabilities and homepage_response:
            print(f"\n🔒 Step 2: Scanning homepage for vulnerabilities...")
            homepage_vulns = self.check_url_security(url, homepage_response)
            all_vulnerabilities.extend(homepage_vulns)

            if homepage_vulns:
                print(
                    f"⚠️ Found {len(homepage_vulns)} potential vulnerabilities on homepage"
                )

        # Step 2b: Domain-level security checks
        if self.check_vulnerabilities:
            print(f"\n🔐 Step 2b: Running domain-level security checks...")

            # SSL/TLS certificate check
            if not self.skip_ssl:
                print("   Checking SSL/TLS certificate...")
                ssl_vulns = self._check_ssl_certificate(url)
                all_vulnerabilities.extend(ssl_vulns)
                if ssl_vulns:
                    print(f"   ⚠️ Found {len(ssl_vulns)} SSL/TLS issues")
                else:
                    print("   ✅ SSL/TLS certificate OK")
            else:
                print("   ⏭️ Skipping SSL/TLS check")

            # CORS misconfiguration check
            print("   Checking CORS configuration...")
            cors_vulns = self._check_cors(url)
            all_vulnerabilities.extend(cors_vulns)
            if cors_vulns:
                print(f"   ⚠️ Found {len(cors_vulns)} CORS issues")
            else:
                print("   ✅ CORS configuration OK")

            # Sensitive file discovery
            if not self.skip_sensitive_files:
                print("   Scanning for exposed sensitive files...")
                sensitive_vulns = self._check_sensitive_files(url)
                all_vulnerabilities.extend(sensitive_vulns)
                if sensitive_vulns:
                    print(f"   🚨 Found {len(sensitive_vulns)} exposed sensitive files!")
                else:
                    print("   ✅ No exposed sensitive files found")
            else:
                print("   ⏭️ Skipping sensitive file scan")

        # Step 3: Check each link status and optionally scan for vulnerabilities
        print(f"\n🔍 Step 3: Checking link status and security...")
        results = []

        if self.threads > 1:
            # Multithreaded scanning
            print(f"   Using {self.threads} threads for parallel scanning...")
            link_list = list(links)
            completed = 0

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.check_url, link): link for link in link_list}

                for future in as_completed(future_to_url):
                    completed += 1
                    link_url, status, error, vulnerabilities = future.result()

                    print(f"[{completed}/{len(link_list)}] {link_url[:60]}...", end=" ")

                    if status == 404:
                        print(f"❌ 404")
                        results.append(("404", link_url, error, []))
                    elif status and status >= 400:
                        print(f"⚠️ {status}")
                        results.append((f"ERROR_{status}", link_url, error, []))
                    elif status and status < 400:
                        vuln_count = len(vulnerabilities)
                        status_msg = f"✅ {status}"
                        if vuln_count > 0:
                            status_msg += f" ({vuln_count} vulns)"
                        print(status_msg)
                        results.append(("OK", link_url, None, vulnerabilities))
                        all_vulnerabilities.extend(vulnerabilities)
                    else:
                        print(f"❌ FAILED")
                        results.append(("FAILED", link_url, error, []))
        else:
            # Sequential scanning
            for i, link_url in enumerate(links, 1):
                print(f"Checking {i}/{len(links)}: {link_url[:80]}...", end=" ")

                link_url, status, error, vulnerabilities = self.check_url(link_url)

                if status == 404:
                    print(f"❌ 404 NOT FOUND")
                    results.append(("404", link_url, error, []))
                elif status and status >= 400:
                    print(f"⚠️  ERROR {status}")
                    results.append((f"ERROR_{status}", link_url, error, []))
                elif status and status < 400:
                    vuln_count = len(vulnerabilities)
                    status_msg = f"✅ OK ({status})"
                    if vuln_count > 0:
                        status_msg += f" ⚠️ {vuln_count} vulns"
                    print(status_msg)
                    results.append(("OK", link_url, None, vulnerabilities))
                    all_vulnerabilities.extend(vulnerabilities)
                else:
                    print(f"❌ FAILED ({error})")
                    results.append(("FAILED", link_url, error, []))

                time.sleep(self.delay)

        return results, all_vulnerabilities

    def generate_report(self, domain, results, vulnerabilities):
        """Generate comprehensive security report"""
        print(f"\n📊 Step 4: Security Report for {domain}")
        print("=" * 60)

        # URL status summary
        ok_count = len([r for r in results if r[0] == "OK"])
        error_404_count = len([r for r in results if r[0] == "404"])
        other_errors_count = len(
            [r for r in results if r[0].startswith("ERROR") or r[0] == "FAILED"]
        )

        print(f"📈 URL Status Summary:")
        print(f"   Total URLs checked: {len(results)}")
        print(f"   ✅ Working URLs: {ok_count}")
        print(f"   🚨 404 errors: {error_404_count}")
        print(f"   ⚠️  Other errors: {other_errors_count}")

        # Vulnerability summary
        if self.check_vulnerabilities:
            critical_vulns = [
                v for v in vulnerabilities if v.get("severity") == "critical"
            ]
            high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
            medium_vulns = [v for v in vulnerabilities if v.get("severity") == "medium"]
            low_vulns = [v for v in vulnerabilities if v.get("severity") == "low"]
            info_vulns = [v for v in vulnerabilities if v.get("severity") == "info"]

            print(f"\n🔒 Security Vulnerability Summary:")
            print(f"   🔴 Critical: {len(critical_vulns)}")
            print(f"   🟠 High: {len(high_vulns)}")
            print(f"   🟡 Medium: {len(medium_vulns)}")
            print(f"   🟢 Low: {len(low_vulns)}")
            print(f"   🔵 Info: {len(info_vulns)}")
            print(f"   📊 Total findings: {len(vulnerabilities)}")

            # Detailed vulnerability report
            if vulnerabilities:
                print(f"\n🚨 Detailed Vulnerability Report:")

                # Group by severity
                for severity in ["critical", "high", "medium", "low", "info"]:
                    sev_vulns = [
                        v for v in vulnerabilities if v.get("severity") == severity
                    ]
                    if sev_vulns:
                        severity_emoji = {
                            "critical": "🔴",
                            "high": "🟠",
                            "medium": "🟡",
                            "low": "🟢",
                            "info": "🔵",
                        }
                        print(
                            f"\n{severity_emoji[severity]} {severity.upper()} SEVERITY:"
                        )

                        for vuln in sev_vulns:
                            print(f"   • {vuln['type']} - {vuln['url']}")
                            if "missing_headers" in vuln:
                                print(
                                    f"     Missing: {', '.join(vuln['missing_headers'])}"
                                )
                            if "server" in vuln:
                                print(f"     Server: {vuln['server']}")
                            if "version" in vuln:
                                print(f"     Version: {vuln['version']}")
                            if "matches" in vuln:
                                print(f"     Matches: {vuln['matches']} occurrences")
                            if "issues" in vuln:
                                print(f"     Issues: {', '.join(vuln['issues'])}")
                            if "details" in vuln:
                                print(f"     Details: {vuln['details']}")
                            if "technologies" in vuln:
                                print(f"     Stack: {', '.join(vuln['technologies'])}")
                            if "description" in vuln:
                                print(f"     Description: {vuln['description']}")
                            if "emails" in vuln:
                                print(f"     Emails: {', '.join(vuln['emails'][:3])}")
                            if "ips" in vuln:
                                print(f"     IPs: {', '.join(vuln['ips'][:3])}")

        # 404 errors
        if error_404_count > 0:
            print(f"\n🚨 404 NOT FOUND URLs:")
            for _, url, _, _ in [r for r in results if r[0] == "404"]:
                print(f"   ❌ {url}")

        # Other errors
        if other_errors_count > 0:
            print(f"\n⚠️ Other Errors:")
            for status, url, error, _ in [
                r for r in results if r[0].startswith("ERROR") or r[0] == "FAILED"
            ]:
                print(f"   ⚠️  {url} - {status}: {error}")

        return {
            "urls": {
                "total": len(results),
                "ok": ok_count,
                "404": error_404_count,
                "other_errors": other_errors_count,
            },
            "vulnerabilities": vulnerabilities,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Security URL checker with vulnerability scanning"
    )
    parser.add_argument("domains", nargs="+", help="Domain names to check")
    parser.add_argument(
        "--delay", type=float, default=1.0, help="Delay between requests (seconds)"
    )
    parser.add_argument(
        "--no-vuln-scan", action="store_true", help="Disable vulnerability scanning"
    )
    parser.add_argument("--export-json", help="Export results to JSON file")
    parser.add_argument(
        "--threads", type=int, default=1, help="Number of concurrent threads for URL checking"
    )
    parser.add_argument(
        "--skip-ssl", action="store_true", help="Skip SSL certificate checks"
    )
    parser.add_argument(
        "--skip-sensitive-files", action="store_true", help="Skip sensitive file scanning"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    checker = SecurityURLChecker(
        delay=args.delay,
        check_vulnerabilities=not args.no_vuln_scan,
        threads=args.threads,
        skip_ssl=args.skip_ssl,
        skip_sensitive_files=args.skip_sensitive_files
    )

    all_reports = {}
    all_vulnerabilities = []
    total_stats = {
        "urls": {"total": 0, "ok": 0, "404": 0, "other_errors": 0},
        "vulnerabilities": [],
    }

    for domain in args.domains:
        results, vulnerabilities = checker.scan_website(domain)
        report = checker.generate_report(domain, results, vulnerabilities)

        all_reports[domain] = report
        all_vulnerabilities.extend(vulnerabilities)

        # Update total stats
        total_stats["urls"]["total"] += report["urls"]["total"]
        total_stats["urls"]["ok"] += report["urls"]["ok"]
        total_stats["urls"]["404"] += report["urls"]["404"]
        total_stats["urls"]["other_errors"] += report["urls"]["other_errors"]

    if len(args.domains) > 1:
        print(f"\n🎯 OVERALL SUMMARY")
        print("=" * 60)
        print(f"📈 Total URLs checked: {total_stats['urls']['total']}")
        print(f"✅ Working URLs: {total_stats['urls']['ok']}")
        print(f"🚨 Total 404 errors: {total_stats['urls']['404']}")
        print(f"⚠️  Other errors: {total_stats['urls']['other_errors']}")

        if checker.check_vulnerabilities:
            critical = len(
                [v for v in all_vulnerabilities if v.get("severity") == "critical"]
            )
            high = len([v for v in all_vulnerabilities if v.get("severity") == "high"])
            medium = len(
                [v for v in all_vulnerabilities if v.get("severity") == "medium"]
            )
            low = len([v for v in all_vulnerabilities if v.get("severity") == "low"])
            info = len([v for v in all_vulnerabilities if v.get("severity") == "info"])

            print(f"\n🔒 Total Security Issues:")
            print(f"   🔴 Critical: {critical}")
            print(f"   🟠 High: {high}")
            print(f"   🟡 Medium: {medium}")
            print(f"   🟢 Low: {low}")
            print(f"   🔵 Info: {info}")
            print(f"   📊 Total findings: {len(all_vulnerabilities)}")

            if critical > 0 or high > 0:
                print(
                    f"\n🚨 CRITICAL/HIGH SECURITY ISSUES FOUND - IMMEDIATE ATTENTION REQUIRED!"
                )

    # Export to JSON if requested
    if args.export_json:
        with open(args.export_json, "w") as f:
            json.dump(
                {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "domains_scanned": args.domains,
                    "total_stats": total_stats,
                    "detailed_reports": all_reports,
                    "all_vulnerabilities": all_vulnerabilities,
                },
                f,
                indent=2,
            )
        print(f"\n📄 Results exported to {args.export_json}")


if __name__ == "__main__":
    main()
