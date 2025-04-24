from http.server import BaseHTTPRequestHandler
import json
import re
from urllib.parse import urlparse
import os
import mimetypes

# List of common trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'github.com', 'paypal.com', 'netflix.com', 'youtube.com',
    'dropbox.com', 'gmail.com', 'outlook.com', 'yahoo.com'
]

def create_default_security_info():
    return {
        'ssl_cert': False,
        'domain_age': 'Unknown',
        'security_headers': {
            'Strict-Transport-Security': False,
            'X-Content-Type-Options': False,
            'X-Frame-Options': False,
            'Content-Security-Policy': False
        },
        'blacklist_status': 'Unknown'
    }

def analyze_url(url):
    try:
        if not url:
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Please enter a valid URL',
                'security_info': create_default_security_info()
            }
        
        # Make sure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
        
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Clean up domain - remove www. prefix and port if present
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if not domain:
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Invalid URL format. Please include a domain (e.g., example.com)',
                'security_info': create_default_security_info()
            }
        
        # First check if this is an exact match to a trusted domain
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted.lower():
                return {
                    'is_phishing': False,
                    'confidence': 0.95,
                    'analysis_note': 'This appears to be a trusted domain',
                    'security_info': {
                        'ssl_cert': url.startswith('https'),
                        'domain_age': 'Established domain',
                        'security_headers': {
                            'Strict-Transport-Security': True,
                            'X-Content-Type-Options': True,
                            'X-Frame-Options': True,
                            'Content-Security-Policy': True
                        },
                        'blacklist_status': 'Not blacklisted'
                    }
                }
        
        # Very simple analysis based on domain patterns
        suspicious_patterns = [
            r'paypa[l1]',
            r'g[o0]{2}g[l1]e',
            r'amaz[o0]n',
            r'faceb[o0]{2}k',
            r'micr[o0]s[o0]ft',
            r'bank.*login',
            r'apple.*verify',
            r'secure.*account'
        ]
        
        # Check for obvious phishing signs
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE) and not any(trusted in domain for trusted in TRUSTED_DOMAINS):
                return {
                    'is_phishing': True,
                    'confidence': 0.85,
                    'analysis_note': 'This domain appears to be mimicking a trusted site',
                    'security_info': {
                        'ssl_cert': url.startswith('https'),
                        'domain_age': 'Unknown',
                        'security_headers': {},
                        'blacklist_status': 'Potentially suspicious'
                    }
                }
        
        # For other domains, provide a neutral response
        return {
            'is_phishing': False,
            'confidence': 0.60,
            'analysis_note': 'This domain does not match known phishing patterns, but we recommend caution',
            'security_info': {
                'ssl_cert': url.startswith('https'),
                'domain_age': 'Unknown',
                'security_headers': {
                    'Strict-Transport-Security': False,
                    'X-Content-Type-Options': False,
                    'X-Frame-Options': False,
                    'Content-Security-Policy': False
                },
                'blacklist_status': 'Not on known blacklists'
            }
        }
        
    except Exception as e:
        return {
            'is_phishing': False,
            'confidence': 0.5,
            'analysis_note': f'Error analyzing URL: {str(e)}',
            'security_info': create_default_security_info()
        }

# Vercel serverless function handler
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        
        # Default to index.html
        if path == '/' or path == '':
            path = '/index.html'
            
        # Determine the file path
        if path.startswith('/static/'):
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), path[1:])
        elif path == '/index.html':
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html')
        else:
            # Try to find the file in static directory
            potential_static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', path[1:])
            if os.path.exists(potential_static_path):
                file_path = potential_static_path
            else:
                # Default to index.html for any other path
                file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html')
        
        # Check if file exists
        if os.path.exists(file_path):
            # Determine content type
            content_type, _ = mimetypes.guess_type(file_path)
            if content_type is None:
                if file_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif file_path.endswith('.css'):
                    content_type = 'text/css'
                else:
                    content_type = 'text/plain'
            
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.end_headers()
            
            # Read and send file content
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            # File not found
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'File not found')
        
    def do_POST(self):
        if self.path == '/analyze':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            url = data.get('url', '').strip()
            result = analyze_url(url)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(404)
            self.end_headers()
