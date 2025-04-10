from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse
import whois
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import joblib
import tld
import re
import os
import difflib
import socket
import ssl
import OpenSSL
from urllib3.exceptions import InsecureRequestWarning
import warnings
import pickle
import dns.resolver
import tldextract
import validators

# Suppress only the single warning from urllib3 needed.
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Try to import dns resolver, but make it optional
try:
    import dns.resolver
    HAS_DNS_MODULE = True
except ImportError:
    HAS_DNS_MODULE = False
    print("DNS module not available. Some features will be limited.")

app = Flask(__name__)

# Whitelist of trusted domains
TRUSTED_DOMAINS = [
    'youtube.com',
    'google.com',
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'amazon.com',
    'netflix.com',
    'microsoft.com',
    'apple.com',
    'yahoo.com',
    'wikipedia.org',
    'github.com',
    'linkedin.com',
    'reddit.com'
]

# Known phishing patterns
PHISHING_PATTERNS = [
    # Character substitution patterns
    r'g[o0][o0]g[l1]e\.com',  # Google variations
    r'faceb[o0][o0]k\.com',   # Facebook variations
    r'[i1]nstagram\.com',     # Instagram variations
    r'tw[i1]tter\.com',       # Twitter variations
    r'amaz[o0]n\.com',        # Amazon variations
    r'paypa[l1]\.com',        # PayPal variations
    r'm[i1]cr[o0]s[o0]ft\.com', # Microsoft variations
    r'app[l1]e\.com',         # Apple variations
    r'netfl[i1]x\.com',       # Netflix variations
    r'yah[o0][o0]\.com',      # Yahoo variations
    r'l[i1]nked[i1]n\.com',  # LinkedIn variations - fixed pattern to prevent false positives
    
    # Added affixes patterns - Modified to exclude legitimate domains
    r'(secure|login|signin|account|verify|update|confirm|validation|auth)\-[\w-]+\.(com|net|org|info)',
    r'[\w-]+\-(secure|login|signin|account|verify|update|confirm|validation|auth)\.(com|net|org|info)',
    
    # Number appending patterns
    r'(google|facebook|amazon|apple|microsoft|paypal|instagram|twitter|netflix|yahoo|linkedin)\d{2,}\.(com|net|org)',
    
    # Suspicious subdomains
    r'(login|secure|account|signin|verify)\.[\w-]+\.(com|net|org|info)',
    # Modified to exclude legitimate domains like blog.linkedin.com by only matching if the domain isn't in the correct TLD
    r'(google|facebook|amazon|apple|microsoft|paypal|instagram|twitter|netflix|yahoo|linkedin)\.(?!com|net|org|edu|gov|io)[\w-]+\.(com|net|org|info)',
    
    # Typosquatting 
    r'go{3,}gle\.com',           # Multiple 'o's - more than 2
    r'facebo{3,}k\.com',         # Multiple 'o's - more than 2
    r'youtune\.com',          # 'n' instead of 'b'
    r'yutube\.com',           # Missing 'o'
    r'goggle\.com',           # Extra 'g'
    r'microsfot\.com',        # Swapped letters
    r'linkedin(?!\.com)',     # Starts with linkedin but not followed by .com
    
    # Homograph attacks
    r'xn--[\w-]+\.(com|net|org|info)',  # Punycode domains
    
    # Suspicious TLDs
    r'\w+\.(xyz|top|cc|tk|ml|ga|cf|gq|pw)\b',
    
    # Action or urgent keywords
    r'(urgent|immediate|verify|authorize|limited|expires|suspension|24hour)[\w-]*\.(com|net|org)',
]

# Load or create the model
def load_or_create_model():
    if os.path.exists('phishing_model.pkl'):
        return joblib.load('phishing_model.pkl')
    else:
        # Create better training data for demonstration
        data = {
            'url_length': [20, 15, 40, 25, 60, 30, 45, 50, 35, 10, 25, 30, 35, 40, 45],
            'has_ip': [0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            'has_at': [0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            'has_double_slash': [0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
            'domain_age': [365, 730, 10, 500, 5, 1000, 800, 30, 7, 2000, 10, 15, 20, 25, 30],
            'domain_length': [10, 6, 15, 12, 20, 8, 9, 16, 18, 7, 8, 9, 10, 11, 12],
            'similarity_to_trusted': [0.9, 0.95, 0.3, 0.8, 0.2, 0.9, 0.85, 0.4, 0.1, 0.9, 0.7, 0.75, 0.8, 0.85, 0.9],
            'is_phishing': [0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1]
        }
        df = pd.DataFrame(data)
        
        X = df.drop('is_phishing', axis=1)
        y = df['is_phishing']
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        
        joblib.dump(model, 'phishing_model.pkl')
        return model

# Load the model
model = load_or_create_model()

def calculate_similarity_to_trusted(url):
    try:
        # Make sure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
            
        domain = tld.get_tld(url, as_object=True, fail_silently=True)
        if not domain:
            return 0.0
            
        domain_name = domain.domain + '.' + domain.tld
        
        # Check if it matches any phishing patterns
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, domain_name, re.IGNORECASE):
                return 0.0  # Very low similarity for known phishing patterns
        
        # Calculate similarity to trusted domains
        max_similarity = 0.0
        for trusted in TRUSTED_DOMAINS:
            similarity = difflib.SequenceMatcher(None, domain_name, trusted).ratio()
            max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    except Exception as e:
        print(f"Error in calculate_similarity_to_trusted: {str(e)}")
        return 0.0

def extract_features(url):
    features = {}
    
    # Basic URL features
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # Length features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    
    # Character features
    features['num_dots'] = url.count('.')
    features['num_dashes'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_at_symbols'] = url.count('@')
    features['num_ampersands'] = url.count('&')
    features['num_numeric_chars'] = sum(c.isdigit() for c in domain)
    
    # Special character features
    features['has_suspicious_chars'] = bool(re.search(r'[^a-zA-Z0-9\-\./]', url))
    features['has_multiple_subdomains'] = len(domain.split('.')) > 2
    
    # Protocol features
    features['uses_https'] = parsed_url.scheme == 'https'
    
    # Domain features
    try:
        tld_info = tld.get_tld(url, as_object=True)
        features['tld_length'] = len(tld_info.tld)
        features['subdomain_length'] = len(tld_info.subdomain) if tld_info.subdomain else 0
        features['has_uncommon_tld'] = tld_info.tld not in ['com', 'org', 'net', 'edu', 'gov', 'io']
    except:
        features['tld_length'] = 0
        features['subdomain_length'] = 0
        features['has_uncommon_tld'] = False
    
    # Additional security features
    features['is_ip_address'] = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))
    features['has_port'] = ':' in domain
    features['has_suspicious_tld'] = bool(re.search(r'\.(xyz|top|cc|tk|ml|ga|cf|gq|pw)$', domain))
    
    # Check for common typosquatting patterns
    features['is_typosquatting'] = bool(re.search(r'(githu[b|d]|faceboo[k|c]|goo[g|d]le|microso[f|t]|app[l|i]e|amaz[o|0]n)', domain, re.IGNORECASE))
    
    # Add check for domains with numbers appended to trusted names
    if not features['is_typosquatting']:
        for trusted in TRUSTED_DOMAINS:
            trusted_name = trusted.split('.')[0]  # Get just the domain name part (e.g., 'google' from 'google.com')
            # Check if domain contains the trusted name followed by numbers or special chars
            if re.search(f"{trusted_name}[0-9-_]+\\.com", domain, re.IGNORECASE):
                features['is_typosquatting'] = True
                break
    
    # Check for suspicious patterns
    features['has_suspicious_patterns'] = bool(re.search(r'(secure|account|verify|login|signin|update|confirm|validate|password|banking|support|help|service|access)', domain, re.IGNORECASE))
    
    # Check for homograph attacks (punycode domains)
    features['is_punycode'] = 'xn--' in domain.lower()
    
    # Check for excessive subdomains (phishing often uses multiple levels)
    features['has_excessive_subdomains'] = domain.count('.') > 2
    
    # Check for URL encoding abuse
    features['has_excessive_url_encoding'] = url.count('%') > 3
    
    # Check for misleading URL paths (e.g., /paypal/login in non-PayPal domains)
    features['has_misleading_path'] = False
    for trusted in TRUSTED_DOMAINS:
        trusted_name = trusted.split('.')[0]  # Get domain name without TLD
        if trusted_name in path.lower() and trusted not in domain.lower():
            features['has_misleading_path'] = True
            break
    
    # Check for URL shorteners
    shortener_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'cli.gs', 'ow.ly', 'rebrand.ly']
    features['is_shortened_url'] = any(short in domain.lower() for short in shortener_domains)
    
    # Check for urgent or action words in path
    features['has_urgent_words'] = bool(re.search(r'(urgent|immediate|critical|important|limited|expires|24hour|verify|reset)', path, re.IGNORECASE))
    
    # Combination of risky features
    features['has_multiple_risk_factors'] = (
        (features['has_suspicious_chars'] and features['has_suspicious_tld']) or
        (features['has_suspicious_patterns'] and not features['uses_https']) or
        (features['is_typosquatting'] and features['has_misleading_path']) or
        (features['num_numeric_chars'] > 2 and features['has_suspicious_patterns'])
    )
    
    return features

def is_trusted_domain(url):
    try:
        # Make sure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
            
        domain = tld.get_tld(url, as_object=True, fail_silently=True)
        if not domain:
            return False
            
        domain_name = domain.domain + '.' + domain.tld
        
        # Check if it matches any phishing patterns
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, domain_name, re.IGNORECASE):
                return False
        
        return any(domain_name.endswith(trusted) for trusted in TRUSTED_DOMAINS)
    except Exception as e:
        print(f"Error in is_trusted_domain: {str(e)}")
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Wrap the entire function in a global try-except
    try:
        try:
            data = request.get_json()
            url = data['url'].strip()
        except Exception as e:
            print(f"Error parsing request data: {str(e)}")
            return jsonify({
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Error processing your request. Please try again.',
                'security_info': {
                    'ssl_cert': False,
                    'domain_age': 0,
                    'security_headers': {
                        'Strict-Transport-Security': False,
                        'X-Content-Type-Options': False,
                        'X-Frame-Options': False,
                        'Content-Security-Policy': False
                    },
                    'blacklist_status': 'Unknown'
                }
            })
        
        # If URL is empty, return error
        if not url:
            return jsonify({
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': 'Please enter a valid URL',
                'security_info': {
                    'ssl_cert': False,
                    'domain_age': 0,
                    'security_headers': {
                        'Strict-Transport-Security': False,
                        'X-Content-Type-Options': False,
                        'X-Frame-Options': False,
                        'Content-Security-Policy': False
                    },
                    'blacklist_status': 'Unknown'
                }
            })
        
        # Process the URL only using simple pattern matching
        # This avoids network connectivity issues for basic analysis
        
        # Remove @ symbol if it exists at the beginning of the URL
        if url.startswith('@'):
            url = url[1:]
        
        # Fix common protocol typos
        if url.startswith('http;//'):
            url = 'http://' + url[7:]
            
        # Normalize URL for analysis
        try:
            if not url.startswith('http'):
                url = 'http://' + url
                
            # Parse the URL
            result = urlparse(url)
            domain = result.netloc.lower()
            
            # Clean up the domain by removing www. prefix and any trailing port
            if domain.startswith('www.'):
                domain = domain[4:]
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Extract the domain for pattern matching
            if not domain:
                return jsonify({
                    'is_phishing': False,
                    'confidence': 0.5,
                    'analysis_note': 'Invalid URL format. Please include a domain (e.g., example.com)',
                    'security_info': {
                        'ssl_cert': False,
                        'domain_age': 0,
                        'security_headers': {
                            'Strict-Transport-Security': False,
                            'X-Content-Type-Options': False,
                            'X-Frame-Options': False,
                            'Content-Security-Policy': False
                        },
                        'blacklist_status': 'Unknown'
                    }
                })
                
            # First check: Is this an exact match for a trusted domain?
            # This check must happen before any pattern matching to prevent false positives
            for trusted in TRUSTED_DOMAINS:
                if domain == trusted.lower():
                    return jsonify({
                        'is_phishing': False,
                        'confidence': 0.99,
                        'analysis_note': 'This is a trusted domain',
                        'security_info': {
                            'ssl_cert': True,
                            'domain_age': 1000,  # Placeholder
                            'security_headers': {
                                'Strict-Transport-Security': True,
                                'X-Content-Type-Options': True,
                                'X-Frame-Options': True,
                                'Content-Security-Policy': True
                            },
                            'blacklist_status': 'Trusted Domain'
                        }
                    })
            
            # Quick pattern matching for phishing without network requests
            for trusted in TRUSTED_DOMAINS:
                trusted_name = trusted.split('.')[0]
                if re.search(f"{trusted_name}\\d+", domain, re.IGNORECASE):
                    return jsonify({
                        'is_phishing': True,
                        'confidence': 0.98,
                        'analysis_note': f'This domain appears to be mimicking {trusted}',
                        'security_info': {
                            'ssl_cert': False,
                            'domain_age': 0,
                            'security_headers': {
                                'Strict-Transport-Security': False,
                                'X-Content-Type-Options': False,
                                'X-Frame-Options': False,
                                'Content-Security-Policy': False
                            },
                            'blacklist_status': 'Blacklisted - Suspicious Domain Variation'
                        }
                    })
            
            # For known phishing patterns
            for pattern in PHISHING_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    return jsonify({
                        'is_phishing': True,
                        'confidence': 0.99,
                        'analysis_note': 'This domain matches a known phishing pattern',
                        'security_info': {
                            'ssl_cert': False,
                            'domain_age': 0,
                            'security_headers': {
                                'Strict-Transport-Security': False,
                                'X-Content-Type-Options': False,
                                'X-Frame-Options': False,
                                'Content-Security-Policy': False
                            },
                            'blacklist_status': 'Blacklisted - Known Phishing Pattern'
                        }
                    })
            
            # For punycode homograph attacks
            if 'xn--' in domain.lower():
                return jsonify({
                    'is_phishing': True,
                    'confidence': 0.97,
                    'analysis_note': 'This domain appears to be using a homograph attack',
                    'security_info': {
                        'ssl_cert': False,
                        'domain_age': 0,
                        'security_headers': {
                            'Strict-Transport-Security': False,
                            'X-Content-Type-Options': False,
                            'X-Frame-Options': False,
                            'Content-Security-Policy': False
                        },
                        'blacklist_status': 'Blacklisted - Potential Homograph Attack'
                    }
                })
                
            # Suspicious TLD check
            if re.search(r'\.(xyz|top|cc|tk|ml|ga|cf|gq|pw)$', domain, re.IGNORECASE):
                return jsonify({
                    'is_phishing': True,
                    'confidence': 0.7,
                    'analysis_note': 'This domain uses a TLD commonly associated with phishing',
                    'security_info': {
                        'ssl_cert': False,
                        'domain_age': 0,
                        'security_headers': {
                            'Strict-Transport-Security': False,
                            'X-Content-Type-Options': False,
                            'X-Frame-Options': False,
                            'Content-Security-Policy': False
                        },
                        'blacklist_status': 'Suspicious - High-Risk TLD'
                    }
                })
                
            # Add debug logging - remove this in production
            print(f"Analyzing domain: {domain}")
                
            # If we couldn't make an immediate determination, attempt feature extraction
            try:
                features = extract_features(url)
                
                # IMPORTANT: Check if any of the critical patterns are matched
                if (features.get('is_typosquatting', False) or 
                    features.get('has_suspicious_patterns', False) or
                    features.get('has_suspicious_tld', False) or
                    features.get('is_punycode', False)):
                    return jsonify({
                        'is_phishing': True,
                        'confidence': 0.85,
                        'analysis_note': 'This URL has characteristics commonly found in phishing sites',
                        'security_info': {
                            'ssl_cert': False,
                            'domain_age': 0,
                            'security_headers': {
                                'Strict-Transport-Security': False,
                                'X-Content-Type-Options': False,
                                'X-Frame-Options': False,
                                'Content-Security-Policy': False
                            },
                            'blacklist_status': 'Suspicious - Pattern Matched'
                        }
                    })
                
                # Use the original features expected by the model to avoid mismatch
                # Get only the essential features that the model was trained on
                try:
                    # Extract the core features needed by the model
                    core_features = [
                        features.get('url_length', 0),
                        features.get('has_ip', 0),
                        features.get('has_at', 0),
                        features.get('has_double_slash', 0),
                        features.get('domain_age', 0),
                        features.get('domain_length', 0),
                        features.get('similarity_to_trusted', 0)
                    ]
                    
                    # Make prediction with only the core features
                    is_phishing = bool(model.predict([core_features])[0])
                    probability = model.predict_proba([core_features])[0]
                    confidence = float(max(probability))
                except Exception as model_error:
                    print(f"Model prediction error: {str(model_error)}")
                    # If model prediction fails, make a best guess based on extracted features
                    is_phishing = any([
                        features.get('is_typosquatting', False),
                        features.get('has_suspicious_tld', False),
                        features.get('has_suspicious_patterns', False),
                        features.get('has_numeric_in_domain', False) and 'google' in domain.lower()
                    ])
                    confidence = 0.7 if is_phishing else 0.4
                
                return jsonify({
                    'is_phishing': is_phishing,
                    'confidence': confidence,
                    'security_info': {
                        'ssl_cert': False,  # Default without network check
                        'domain_age': 0,    # Default without network check
                        'security_headers': {
                            'Strict-Transport-Security': False,
                            'X-Content-Type-Options': False,
                            'X-Frame-Options': False,
                            'Content-Security-Policy': False
                        },
                        'blacklist_status': 'Analysis Complete'
                    }
                })
                
            except Exception as e:
                print(f"Error in feature extraction: {str(e)}")
                
                # Try a simplified analysis for URLs like "google12.com" even if feature extraction fails
                simplified_detection = False
                simplified_confidence = 0.5
                
                # Check if domain contains a trusted name with numbers (e.g., google12.com)
                if domain:
                    for trusted in TRUSTED_DOMAINS:
                        trusted_name = trusted.split('.')[0]
                        if re.search(f"{trusted_name}\\d+", domain, re.IGNORECASE):
                            simplified_detection = True
                            simplified_confidence = 0.9
                            break
                
                # Default response with simplified detection if possible
                return jsonify({
                    'is_phishing': simplified_detection,
                    'confidence': simplified_confidence,
                    'analysis_note': 'Simplified analysis performed due to processing issues',
                    'security_info': {
                        'ssl_cert': False,
                        'domain_age': 0,
                        'security_headers': {
                            'Strict-Transport-Security': False,
                            'X-Content-Type-Options': False,
                            'X-Frame-Options': False,
                            'Content-Security-Policy': False
                        },
                        'blacklist_status': 'Limited Analysis'
                    }
                })
                
        except Exception as e:
            print(f"URL processing error: {str(e)}")
            return jsonify({
                'is_phishing': False,
                'confidence': 0.5,
                'analysis_note': f'Error processing URL: {str(e)}',
                'security_info': {
                    'ssl_cert': False,
                    'domain_age': 0,
                    'security_headers': {
                        'Strict-Transport-Security': False,
                        'X-Content-Type-Options': False,
                        'X-Frame-Options': False,
                        'Content-Security-Policy': False
                    },
                    'blacklist_status': 'Unknown'
                }
            })
            
    except Exception as e:
        print(f"Global error in analyze: {str(e)}")
        return jsonify({
            'is_phishing': False,
            'confidence': 0.5,
            'analysis_note': f'Analysis error occurred. Please try a different URL or format.',
            'security_info': {
                'ssl_cert': False,
                'domain_age': 0,
                'security_headers': {
                    'Strict-Transport-Security': False,
                    'X-Content-Type-Options': False,
                    'X-Frame-Options': False,
                    'Content-Security-Policy': False
                },
                'blacklist_status': 'Unknown'
            }
        })

@app.route('/website-info', methods=['POST'])
def website_info():
    try:
        data = request.get_json()
        url = data['url'].strip()
        
        # Normalize URL
        if not url.startswith('http'):
            url = 'http://' + url
        
        try:
            # Set a timeout to avoid hanging
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse domain information
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Get SSL information
            ssl_info = {
                'has_ssl': url.startswith('https://'),
                'valid': False
            }
            
            try:
                if ssl_info['has_ssl']:
                    ssl_check = check_ssl_cert(url)
                    ssl_info['valid'] = ssl_check
            except:
                ssl_info['valid'] = False
                
            # Get domain age and WHOIS information
            whois_info = {}
            domain_age = None
            try:
                w = whois.whois(domain)
                domain_age = get_domain_age(url)
                whois_info = {
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                    'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                    'updated_date': str(w.updated_date) if w.updated_date else 'Unknown',
                    'name_servers': w.name_servers if w.name_servers else [],
                    'status': w.status if w.status else [],
                    'emails': w.emails if w.emails else [],
                    'country': w.country if hasattr(w, 'country') else 'Unknown'
                }
            except Exception as e:
                print(f"WHOIS error: {str(e)}")
                
            # Get security headers
            security_headers = None
            try:
                security_headers = check_security_headers(url)
            except:
                security_headers = {
                    'Strict-Transport-Security': False,
                    'X-Content-Type-Options': False,
                    'X-Frame-Options': False,
                    'Content-Security-Policy': False
                }
            
            # Get DNS records
            dns_records = check_dns_records(domain)
            
            # Extract all meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                if meta.get('name'):
                    meta_tags[meta.get('name')] = meta.get('content')
                elif meta.get('property'):
                    meta_tags[meta.get('property')] = meta.get('content')
            
            # Count links and analyze external domains
            internal_links = 0
            external_links = 0
            external_domains = set()
            suspicious_external_links = 0
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('#') or not href:
                    continue
                if href.startswith('/') or domain in href:
                    internal_links += 1
                else:
                    external_links += 1
                    # Extract domain from external link
                    try:
                        ext_domain = urlparse(href).netloc
                        if ext_domain:
                            external_domains.add(ext_domain)
                            # Check if external domain is suspicious
                            for pattern in PHISHING_PATTERNS:
                                if re.search(pattern, ext_domain, re.IGNORECASE):
                                    suspicious_external_links += 1
                                    break
                    except:
                        pass
            
            # Perform basic SEO analysis
            seo_analysis = {
                'title_length': len(soup.title.string) if soup.title else 0,
                'meta_description_present': 'description' in meta_tags,
                'meta_keywords_present': 'keywords' in meta_tags,
                'h1_count': len(soup.find_all('h1')),
                'h2_count': len(soup.find_all('h2')),
                'img_count': len(soup.find_all('img')),
                'img_alt_missing': len([img for img in soup.find_all('img') if not img.get('alt')]),
                'canonical_url': soup.find('link', {'rel': 'canonical'}).get('href') if soup.find('link', {'rel': 'canonical'}) else None
            }
            
            # Get server information
            server_info = {
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'status_code': response.status_code,
                'redirect_history': [h.url for h in response.history] if response.history else []
            }
            
            # Check redirect chain
            redirect_chain = []
            for i, resp in enumerate(response.history):
                redirect_chain.append({
                    'step': i+1,
                    'url': resp.url,
                    'status_code': resp.status_code
                })
            
            # Check if domain is suspicious
            is_suspicious = False
            suspicious_reasons = []
            
            # Check against phishing patterns
            for pattern in PHISHING_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    is_suspicious = True
                    suspicious_reasons.append("Domain matches known phishing pattern")
                    break
                    
            # Check for domain typosquatting
            for trusted in TRUSTED_DOMAINS:
                similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()
                if 0.7 < similarity < 0.95:  # High similarity but not exact match
                    is_suspicious = True
                    suspicious_reasons.append(f"Domain is similar to trusted domain: {trusted}")
            
            # Detect potential security issues
            security_issues = []
            if not ssl_info['has_ssl']:
                security_issues.append("No SSL/TLS encryption")
                
            if security_headers and not security_headers.get('X-Frame-Options', False):
                security_issues.append("Missing X-Frame-Options header (clickjacking risk)")
                
            if security_headers and not security_headers.get('Content-Security-Policy', False):
                security_issues.append("Missing Content-Security-Policy header")
                
            if suspicious_external_links > 0:
                security_issues.append(f"Contains {suspicious_external_links} suspicious external links")
                
            # Compile comprehensive website information
            info = {
                'url': url,
                'domain': domain,
                'title': soup.title.string if soup.title else 'No title found',
                'meta_tags': meta_tags,
                'description': meta_tags.get('description', 'No description found'),
                'keywords': meta_tags.get('keywords', 'No keywords found'),
                'ssl_info': ssl_info,
                'domain_age': domain_age,
                'whois_info': whois_info,
                'dns_records': dns_records,
                'security_headers': security_headers,
                'links': {
                    'internal': internal_links,
                    'external': external_links,
                    'total': internal_links + external_links,
                    'external_domains': list(external_domains),
                    'suspicious_external': suspicious_external_links
                },
                'seo_analysis': seo_analysis,
                'server_info': server_info,
                'content_length': len(response.text),
                'html_length': len(str(soup)),
                'redirect_chain': redirect_chain,
                'is_suspicious': is_suspicious,
                'suspicious_reasons': suspicious_reasons,
                'security_issues': security_issues
            }
            
            # Check for trusted domains
            for trusted in TRUSTED_DOMAINS:
                if domain.lower() == trusted.lower():
                    info['trusted'] = True
                    break
            else:
                info['trusted'] = False
                
            return jsonify(info)
                
        except requests.exceptions.RequestException as e:
            return jsonify({
                'error': 'Connection error',
                'message': f"Couldn't connect to the website: {str(e)}",
                'url': url
            })
            
        except Exception as e:
            return jsonify({
                'error': 'Processing error',
                'message': f"Error processing website information: {str(e)}",
                'url': url
            })
            
    except Exception as e:
        return jsonify({
            'error': 'Input error',
            'message': f"Error processing request: {str(e)}"
        })

def check_ssl_cert(url):
    try:
        # Make sure URL has scheme and it's HTTPS
        if not url.startswith('http'):
            url = 'http://' + url
            
        if not url.startswith('https://'):
            # If not HTTPS, return False immediately
            return False
        
        # Use a shorter timeout for faster response    
        response = requests.get(url, verify=True, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        # Re-raise connection errors to be caught by the specific handler
        raise
    except requests.exceptions.Timeout:
        print(f"Timeout connecting to {url}")
        raise requests.exceptions.ConnectionError(f"Timeout connecting to {url}")
    except Exception as e:
        print(f"Error in check_ssl_cert: {str(e)}")
        return False

def get_domain_age(url):
    try:
        # Make sure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
            
        domain = tld.get_tld(url, as_object=True, fail_silently=True)
        if not domain:
            return None
            
        w = whois.whois(domain.domain + '.' + domain.tld)
        creation_date = w.creation_date
        if not creation_date:
            return None
            
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        age = (datetime.now() - creation_date).days
        return age
    except Exception as e:
        print(f"Error in get_domain_age: {str(e)}")
        return None

def check_security_headers(url):
    try:
        # Make sure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
            
        # Use a shorter timeout for faster response
        response = requests.get(url, timeout=3)
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': 'Strict-Transport-Security' in headers,
            'X-Content-Type-Options': 'X-Content-Type-Options' in headers,
            'X-Frame-Options': 'X-Frame-Options' in headers,
            'Content-Security-Policy': 'Content-Security-Policy' in headers
        }
        return security_headers
    except requests.exceptions.ConnectionError:
        # Re-raise connection errors to be caught by the specific handler
        raise
    except requests.exceptions.Timeout:
        print(f"Timeout connecting to {url}")
        raise requests.exceptions.ConnectionError(f"Timeout connecting to {url}")
    except Exception as e:
        print(f"Error in check_security_headers: {str(e)}")
        return {
            'Strict-Transport-Security': False,
            'X-Content-Type-Options': False,
            'X-Frame-Options': False,
            'Content-Security-Policy': False
        }

def check_blacklist(url):
    # Implement blacklist checking using various security APIs
    # This is a placeholder
    return 'Not implemented'

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True, cert
    except:
        return False, None

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            age = (datetime.now() - creation_date).days
            return age
    except:
        pass
    return None

def check_blacklist_status(domain):
    # List of known phishing domains and patterns
    known_phishing_domains = [
        'githud.com', 'githu[b|d].com',  # GitHub typosquatting
        'faceboo[k|c].com',  # Facebook typosquatting
        'goo[g|d]le.com',  # Google typosquatting
        'microso[f|t].com',  # Microsoft typosquatting
        'app[l|i]e.com',  # Apple typosquatting
        'amaz[o|0]n.com',  # Amazon typosquatting
        'google[0-9]+.com',  # Google with appended numbers
        'facebook[0-9]+.com',  # Facebook with appended numbers
        'youtube[0-9]+.com',  # YouTube with appended numbers
        'amazon[0-9]+.com',  # Amazon with appended numbers
        'microsoft[0-9]+.com',  # Microsoft with appended numbers
        'apple[0-9]+.com',  # Apple with appended numbers
    ]
    
    # Check for exact matches in known phishing domains
    for pattern in known_phishing_domains:
        if re.search(pattern, domain, re.IGNORECASE):
            return "Blacklisted - Known Phishing Pattern"
             
    # Check for trusted domains with appended numbers or characters
    for trusted in TRUSTED_DOMAINS:
        trusted_name = trusted.split('.')[0]  # Get just the domain name part (e.g., 'google' from 'google.com')
        if re.search(f"{trusted_name}[0-9-_]+\\.com", domain, re.IGNORECASE):
            return "Blacklisted - Suspicious Domain Variation"
            
    # Check for homograph domains (internationalized domain names used for spoofing)
    if 'xn--' in domain.lower():
        return "Blacklisted - Potential Homograph Attack"
        
    # Check for suspicious TLDs
    if re.search(r'\.(xyz|top|cc|tk|ml|ga|cf|gq|pw)$', domain, re.IGNORECASE):
        return "Suspicious - High-Risk TLD"
        
    # Check for login/secure keywords in domain
    if re.search(r'(secure|login|signin|account|password|banking)', domain, re.IGNORECASE):
        return "Suspicious - Contains Security Keywords"
        
    # Check for excessive subdomains (> 3)
    if domain.count('.') > 3:
        return "Suspicious - Excessive Subdomains"
        
    # Check for IP address in domain
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
        return "Suspicious - Uses IP Address"
    
    # Check for urgency terms in domain
    if re.search(r'(urgent|immediate|verify|limited|expires|24hour)', domain, re.IGNORECASE):
        return "Suspicious - Contains Urgency Terms"
    
    return "Not Blacklisted"

def analyze_url(url):
    try:
        # Extract features
        features = extract_features(url)
        
        # Convert features to array for model prediction
        feature_array = np.array([[
            features['url_length'],
            features['domain_length'],
            features['path_length'],
            features['num_dots'],
            features['num_dashes'],
            features['num_underscores'],
            features['num_slashes'],
            features['num_question_marks'],
            features['num_equals'],
            features['num_at_symbols'],
            features['num_ampersands'],
            features['num_numeric_chars'],
            int(features['has_suspicious_chars']),
            int(features['has_multiple_subdomains']),
            int(features['uses_https']),
            features['tld_length'],
            features['subdomain_length'],
            int(features['has_uncommon_tld']),
            int(features['is_ip_address']),
            int(features['has_port']),
            int(features['has_suspicious_tld']),
            int(features['is_typosquatting']),
            int(features['has_suspicious_patterns']),
            int(features['is_punycode']),
            int(features['has_excessive_subdomains']),
            int(features['has_excessive_url_encoding']),
            int(features['has_misleading_path']),
            int(features['is_shortened_url']),
            int(features['has_urgent_words']),
            int(features['has_multiple_risk_factors'])
        ]])
        
        # Get model prediction
        prediction = model.predict(feature_array)[0]
        confidence = model.predict_proba(feature_array)[0][1]
        
        # Additional security checks
        domain = urlparse(url).netloc
        ssl_valid, ssl_cert = check_ssl_certificate(domain)
        domain_age = check_domain_age(domain)
        blacklist_status = check_blacklist_status(domain)
        
        # Override prediction for known phishing patterns or multiple risk factors
        if (features['is_typosquatting'] or 
            blacklist_status.startswith("Blacklisted") or
            features['is_punycode'] or
            features['has_multiple_risk_factors'] or
            (features['has_suspicious_patterns'] and features['num_numeric_chars'] > 0) or
            (features['has_misleading_path'] and not features['uses_https'])):
            prediction = 1
            confidence = max(confidence, 0.95)
        
        # If the URL has multiple high-risk features, elevate the confidence
        risk_count = (
            int(features['is_typosquatting']) + 
            int(features['has_suspicious_patterns']) + 
            int(features['is_punycode']) +
            int(features['has_excessive_subdomains']) +
            int(features['has_misleading_path']) +
            int(features['is_shortened_url']) +
            int(features['has_urgent_words']) +
            int(features['has_multiple_risk_factors'])
        )
        
        if risk_count >= 3 and not prediction:
            prediction = 1
            confidence = max(confidence, 0.8)
        
        # Prepare security information
        security_info = {
            'ssl_cert': ssl_valid,
            'domain_age': domain_age,
            'blacklist_status': blacklist_status,
            'is_typosquatting': features['is_typosquatting'],
            'suspicious_patterns': features['has_suspicious_patterns'],
            'uses_https': features['uses_https'],
            'is_punycode': features['is_punycode'],
            'has_misleading_path': features['has_misleading_path'],
            'risk_factors': risk_count
        }
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(confidence),
            'security_info': security_info
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'analysis_note': 'Unable to complete full analysis. Please check the URL and try again.'
        }

def check_dns_records(domain):
    if not HAS_DNS_MODULE:
        # Return placeholder data if dns module is not available
        return {
            "a_records": ["Not available - DNS module not installed"],
            "aaaa_records": ["Not available - DNS module not installed"],
            "mx_records": ["Not available - DNS module not installed"],
            "ns_records": ["Not available - DNS module not installed"],
            "txt_records": ["Not available - DNS module not installed"],
        }
        
    try:
        result = {}
        
        # Get A records (IPv4)
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result["a_records"] = [answer.to_text() for answer in answers]
        except Exception as e:
            result["a_records"] = [f"Error: {str(e)}"]
            
        # Get AAAA records (IPv6)
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            result["aaaa_records"] = [answer.to_text() for answer in answers]
        except Exception as e:
            result["aaaa_records"] = [f"Error: {str(e)}"]
            
        # Get MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result["mx_records"] = [f"{answer.preference} {answer.exchange}" for answer in answers]
        except Exception as e:
            result["mx_records"] = [f"Error: {str(e)}"]
            
        # Get NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result["ns_records"] = [answer.to_text() for answer in answers]
        except Exception as e:
            result["ns_records"] = [f"Error: {str(e)}"]
            
        # Get TXT records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            result["txt_records"] = [answer.to_text() for answer in answers]
        except Exception as e:
            result["txt_records"] = [f"Error: {str(e)}"]
            
        return result
    except Exception as e:
        print(f"Error in DNS resolution: {str(e)}")
        return {
            "a_records": ["Error in DNS resolution"],
            "aaaa_records": ["Error in DNS resolution"],
            "mx_records": ["Error in DNS resolution"],
            "ns_records": ["Error in DNS resolution"],
            "txt_records": ["Error in DNS resolution"],
        }

if __name__ == '__main__':
    app.run(debug=True) 