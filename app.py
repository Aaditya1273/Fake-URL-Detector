from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
from urllib.parse import urlparse
from difflib import SequenceMatcher
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

try:
    model = joblib.load("phishing_url_detector.pkl")
    logging.info("Model loaded successfully!")
except Exception as e:
    logging.error(f"Error loading model: {e}")
    raise

KNOWN_DOMAINS = ["google.com", "youtube.com", "facebook.com", "amazon.com", "github.com"]

def is_typosquatting(url):
    domain = urlparse(url).netloc
    for known_domain in KNOWN_DOMAINS:
        if SequenceMatcher(None, domain, known_domain).ratio() > 0.8:
            return 1
    return 0

def contains_suspicious_keywords(url):
    suspicious_keywords = ["login", "account", "verify", "password", "update"]
    return any(keyword in url for keyword in suspicious_keywords)

def extract_features(url):
    try:
        features = {
            'url_length': len(url),
            'https': 1 if url.startswith('https') else 0,
            'special_chars': len([char for char in url if not char.isalnum()]),
            'domain_age': 0,
            'typosquatting': is_typosquatting(url),
            'suspicious_keywords': contains_suspicious_keywords(url),
        }
        return pd.DataFrame([features])
    except Exception as e:
        logging.error(f"Error in extract_features: {e}")
        raise

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url or not is_valid_url(url):
            return jsonify({"error": "Invalid URL. Please enter a valid URL."}), 400
        
        logging.debug(f"Received URL: {url}")
        
        features_df = extract_features(url)
        logging.debug("Extracted Features:")
        logging.debug(features_df)
        
        prediction = model.predict(features_df)
        logging.debug(f"Prediction: {prediction}")
        
        result = "Phishing" if prediction[0] == 1 else "Legitimate"
        return jsonify({"url": url, "prediction": result})
    
    except Exception as e:
        logging.error(f"Error in /predict: {e}", exc_info=True)
        return jsonify({"error": "An error occurred. Please try again."}), 500

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

if __name__ == '__main__':
    app.run(debug=True)