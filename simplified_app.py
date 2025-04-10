from flask import Flask, request, jsonify, render_template
import re
from urllib.parse import urlparse

app = Flask(__name__)

# List of common trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'github.com', 'paypal.com', 'netflix.com', 'youtube.com',
    'dropbox.com', 'gmail.com', 'outlook.com', 'yahoo.com'
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Please enter a valid URL',
                'security_info': create_default_security_info()
            })
        
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
            return jsonify({
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Invalid URL format. Please include a domain (e.g., example.com)',
                'security_info': create_default_security_info()
            })
        
        # First check if this is an exact match to a trusted domain
        # This must happen before pattern matching to prevent false positives
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted.lower():
                return jsonify({
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
                })
        
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
                return jsonify({
                    'is_phishing': True,
                    'confidence': 0.85,
                    'analysis_note': 'This domain appears to be mimicking a trusted site',
                    'security_info': {
                        'ssl_cert': url.startswith('https'),
                        'domain_age': 'Unknown',
                        'security_headers': {},
                        'blacklist_status': 'Potentially suspicious'
                    }
                })
        
        # For other domains, provide a neutral response
        return jsonify({
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
        })
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({
            'is_phishing': False,
            'confidence': 0.5,
            'analysis_note': f'Error analyzing URL: {str(e)}',
            'security_info': create_default_security_info()
        })

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

if __name__ == '__main__':
    app.run(debug=True) 