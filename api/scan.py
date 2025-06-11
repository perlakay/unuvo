from http.server import BaseHTTPRequestHandler
import json
import urllib.request
import urllib.parse
import ssl
import socket
from datetime import datetime
import base64

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # Parse request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            url = data.get('url')
            token = data.get('token')
            
            if not url:
                self.send_error_response(400, "URL is required")
                return
            
            # Validate URL format
            try:
                urllib.parse.urlparse(url)
            except:
                self.send_error_response(400, "Invalid URL format")
                return
            
            # Perform security scan
            scan_result = self.perform_security_scan(url, token)
            
            # Send successful response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            response = {
                "success": True,
                "scanId": self.generate_scan_id(),
                "data": scan_result
            }
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            print(f"Scan error: {e}")
            self.send_error_response(500, "Failed to perform security scan")
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def send_error_response(self, status_code, message):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        error_response = {"error": message}
        self.wfile.write(json.dumps(error_response).encode('utf-8'))
    
    def generate_scan_id(self):
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    
    def perform_security_scan(self, url, token=None):
        vulnerabilities = []
        vuln_id = 1
        
        # SSL Security Check
        ssl_issues = self.check_ssl_security(url)
        for issue in ssl_issues:
            vulnerabilities.append({
                "id": vuln_id,
                "title": issue["title"],
                "severity": issue["severity"].lower(),
                "category": "SSL/TLS",
                "description": issue["details"],
                "impact": issue["impact"],
                "remediation": issue["mitigation"]
            })
            vuln_id += 1
        
        # Security Headers Check
        header_issues = self.check_security_headers(url)
        for issue in header_issues:
            vulnerabilities.append({
                "id": vuln_id,
                "title": issue["title"],
                "severity": issue["severity"].lower(),
                "category": "Security Headers",
                "description": issue["details"],
                "impact": issue["impact"],
                "remediation": issue["mitigation"]
            })
            vuln_id += 1
        
        # JWT Analysis (if token provided)
        if token:
            jwt_issues = self.analyze_jwt_token(token)
            for issue in jwt_issues:
                vulnerabilities.append({
                    "id": vuln_id,
                    "title": issue["title"],
                    "severity": issue["severity"].lower(),
                    "category": "JWT",
                    "description": issue["details"],
                    "impact": issue["impact"],
                    "remediation": issue["mitigation"]
                })
                vuln_id += 1
        
        # Calculate security metrics
        critical = len([v for v in vulnerabilities if v["severity"] == "critical"])
        high = len([v for v in vulnerabilities if v["severity"] == "high"])
        medium = len([v for v in vulnerabilities if v["severity"] == "medium"])
        low = len([v for v in vulnerabilities if v["severity"] == "low"])
        
        total_vulns = len(vulnerabilities)
        weighted_score = critical * 25 + high * 15 + medium * 8 + low * 3
        security_score = max(0, 100 - weighted_score) if total_vulns > 0 else 100
        
        return {
            "url": url,
            "scanDate": datetime.now().isoformat(),
            "securityScore": security_score,
            "totalVulnerabilities": total_vulns,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "vulnerabilities": vulnerabilities
        }
    
    def check_ssl_security(self, url):
        issues = []
        
        try:
            # Check if HTTPS is used
            if not url.startswith("https://"):
                issues.append({
                    "title": "Insecure HTTP Connection",
                    "severity": "HIGH",
                    "details": "Website is not using HTTPS encryption",
                    "impact": "Data transmitted between client and server is not encrypted and can be intercepted",
                    "mitigation": "Implement HTTPS with a valid SSL/TLS certificate"
                })
            else:
                # Try to make HTTPS request
                try:
                    req = urllib.request.Request(url, method='HEAD')
                    urllib.request.urlopen(req, timeout=10)
                except Exception as e:
                    if "certificate" in str(e).lower() or "ssl" in str(e).lower():
                        issues.append({
                            "title": "SSL/TLS Certificate Issue",
                            "severity": "HIGH",
                            "details": f"SSL certificate validation failed: {str(e)}",
                            "impact": "Potential SSL/TLS configuration problems that could affect security",
                            "mitigation": "Verify SSL certificate is valid and properly configured"
                        })
        except Exception as e:
            issues.append({
                "title": "SSL/TLS Connection Issue",
                "severity": "MEDIUM",
                "details": f"Unable to verify SSL configuration: {str(e)}",
                "impact": "Could not assess SSL/TLS security",
                "mitigation": "Ensure the URL is accessible and properly configured"
            })
        
        return issues
    
    def check_security_headers(self, url):
        issues = []
        
        try:
            req = urllib.request.Request(url, method='HEAD')
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            
            # Convert header names to lowercase for case-insensitive checking
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            security_headers = {
                "strict-transport-security": "Missing HSTS header - clients may connect over insecure HTTP",
                "x-content-type-options": "Missing protection against MIME-type sniffing attacks",
                "x-frame-options": "Missing clickjacking protection",
                "content-security-policy": "Missing CSP - vulnerable to XSS and injection attacks",
                "x-xss-protection": "Missing XSS protection header",
                "referrer-policy": "Missing referrer policy - may leak sensitive data"
            }
            
            for header, description in security_headers.items():
                if header not in headers_lower:
                    issues.append({
                        "title": f"Missing {header.replace('-', ' ').title()} Header",
                        "severity": "MEDIUM",
                        "details": description,
                        "impact": "Could lead to various security vulnerabilities",
                        "mitigation": f"Add the {header} header with appropriate security values"
                    })
        
        except Exception as e:
            issues.append({
                "title": "Security Headers Check Failed",
                "severity": "LOW",
                "details": f"Failed to check security headers: {str(e)}",
                "impact": "Unable to verify security header configuration",
                "mitigation": "Ensure the URL is accessible and properly configured"
            })
        
        return issues
    
    def analyze_jwt_token(self, token):
        issues = []
        
        try:
            # Basic JWT structure validation
            parts = token.split(".")
            if len(parts) != 3:
                issues.append({
                    "title": "Invalid JWT Structure",
                    "severity": "HIGH",
                    "details": "JWT token does not have the required 3 parts (header.payload.signature)",
                    "impact": "Malformed token could indicate security issues",
                    "mitigation": "Ensure JWT tokens follow the standard format"
                })
                return issues
            
            # Decode header and payload (without verification)
            try:
                # Add padding if needed
                header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                
                header = json.loads(base64.urlsafe_b64decode(header_padded).decode('utf-8'))
                payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode('utf-8'))
                
                # Check algorithm
                if header.get('alg') == 'none':
                    issues.append({
                        "title": "JWT Algorithm 'none'",
                        "severity": "CRITICAL",
                        "details": "Token uses 'none' algorithm which bypasses signature verification",
                        "impact": "Attackers can forge valid tokens without knowing the secret key",
                        "mitigation": "Use strong algorithms like RS256 or ES256, never accept 'none'"
                    })
                
                # Check expiration
                if 'exp' not in payload:
                    issues.append({
                        "title": "Missing Token Expiration",
                        "severity": "MEDIUM",
                        "details": "JWT token does not include an expiration time (exp claim)",
                        "impact": "Token remains valid indefinitely if compromised",
                        "mitigation": "Add reasonable expiration time using 'exp' claim"
                    })
                else:
                    import time
                    now = int(time.time())
                    if payload['exp'] < now:
                        issues.append({
                            "title": "Expired JWT Token",
                            "severity": "LOW",
                            "details": "JWT token has expired",
                            "impact": "Expired tokens should not be accepted",
                            "mitigation": "Implement proper token refresh mechanisms"
                        })
            
            except Exception as decode_error:
                issues.append({
                    "title": "JWT Decoding Failed",
                    "severity": "MEDIUM",
                    "details": f"Failed to decode JWT token: {str(decode_error)}",
                    "impact": "Unable to analyze JWT token structure",
                    "mitigation": "Ensure valid JWT token format"
                })
        
        except Exception as e:
            issues.append({
                "title": "JWT Analysis Failed",
                "severity": "LOW",
                "details": f"Failed to analyze JWT token: {str(e)}",
                "impact": "Unable to verify JWT security configuration",
                "mitigation": "Ensure valid JWT token format"
            })
        
        return issues
