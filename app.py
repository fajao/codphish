import os
import re
import pandas as pd
import joblib
import whois
import tldextract
from datetime import datetime
import pytz
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlparse
from google.cloud import storage
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging
from logging.handlers import SysLogHandler
import validators

# Extract Features from a URL
def extract_features(url):
    features = {
        'whois_regDate': get_whois_reg_date(url),
        'whois_expDate': get_whois_exp_date(url),
        'number_of.': url.count('.'),
        'url_length': len(url),
        'number_of_digits': sum(c.isdigit() for c in url),
        'number_of_special_charac': get_special_char_count(url),
        'number_of-': url.count('-'),
        'number_of//': url.count('//'),
        'number_of/': url.count('/'),
        'number_of@': url.count('@'),
        'number_of_.com': url.count('.com'),
        'number_of_www': url.count('www'),
        'number_of_subdomains': get_subdomain_count(url),
        'IP_in_URL': having_ip_address(url),
        'HTTP_check': get_protocol(url)
    }
    return pd.DataFrame([features])

# FEATURE FUNCTIONS

# Extracting whois/external features from URL
# Website age in days using URL created_date
def get_whois_reg_date(url):
    try:
        whois_result = whois.whois(url)
    except Exception:
        return -1

    created_date = whois_result.creation_date

    if created_date:
        if isinstance(created_date, list):
            created_date = created_date[0]

        if isinstance(created_date, str):
            try:
                created_date = datetime.datetime.strptime(created_date, "%Y-%m-%d")
            except ValueError:
                try:
                    created_date = datetime.datetime.strptime(created_date, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return -1

        if isinstance(created_date, datetime):
            today_date = datetime.now()
            days = (today_date - created_date).days
            return days
        else:
            return -1
    else:
        return -1

# Website expiry date in days using URL expiration_date
def get_whois_exp_date(url):
    try:
        whois_result = whois.whois(url)
    except Exception:
        return -1

    expiration_date = whois_result.expiration_date

    if expiration_date:
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except ValueError:
                try:
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return -1

        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=pytz.UTC)

        today_date = datetime.now(pytz.UTC)

        days = (expiration_date - today_date).days
        return days

    return -1

# Extracting lexical features from URLs
# Number of special characters = ';', '+=', '_', '?', '=', '&', '[', ']'
def get_special_char_count(url):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count

# HTTP check
def get_protocol(url):
    protocol = urlparse(url)
    if(protocol.scheme == 'http'):
        return 1
    else:
        return 0

# Number of subdomains (excluding "www")
def get_subdomain_count(url):
    # Extract the parts of the domain
    extracted = tldextract.extract(url)   
    # Strip 'www' from the subdomain part if present
    subdomain = extracted.subdomain.lstrip('www.')
    # Count the subdomains
    if subdomain: 
        subdomain_count = len(subdomain.split('.'))
    else:
        subdomain_count = 0
    return subdomain_count

# IPv4/IPv6 in URL check
def having_ip_address(url):
    # Regular expression for matching IPv4 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # Regular expression for matching IPv6 addresses
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b::(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'
    # Combine both patterns
    combined_pattern = f'({ipv4_pattern})|({ipv6_pattern})'
    
    # Search for either pattern in the URL
    return int(bool(re.search(combined_pattern, url)))

#########################################################################################

# Database setup
Base = declarative_base()

class URLCheck(Base):
    __tablename__ = 'url_checks'
    id = Column(Integer, primary_key=True)
    url = Column(String)
    prediction = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Database connection
def get_db_connection():
    db_user = os.environ.get('DB_USER')
    db_pass = os.environ.get('DB_PASS')
    db_name = os.environ.get('DB_NAME')
    instance_connection_name = os.environ.get('INSTANCE_CONNECTION_NAME')
    
    connection_string = f"postgresql://{db_user}:{db_pass}@/{db_name}?host=/cloudsql/{instance_connection_name}"
    
    engine = create_engine(connection_string)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)

# Load the Model
def load_model():
    client = storage.Client()
    bucket = client.bucket(os.environ.get('BUCKET_NAME'))
    blob = bucket.blob('final_model.pkl')
    blob.download_to_filename('/tmp/final_model.pkl')
    return joblib.load('/tmp/final_model.pkl')

# Set up logging
#logger = logging.getLogger(__name__)
#logger.setLevel(logging.INFO)
#syslog_handler = SysLogHandler(address=('your_graylog_server', 514))
#logger.addHandler(syslog_handler)

# Flask Service
app = Flask(__name__, static_folder='static')
loaded_model = load_model()
SessionLocal = get_db_connection()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if path != 'favicon.ico':
        return send_from_directory(app.static_folder, path)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.json['url']

    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400
    
    url_features = extract_features(url)
    prediction = loaded_model.predict(url_features)
    result = 'Suspicious' if prediction[0] else 'Safe'

    #logger.info(f"Prediction made for URL: {url}, Result: {result}")
    #return jsonify({'url': url, 'prediction': result})
    
    # Store the result in the database
    session = SessionLocal()
    new_check = URLCheck(url=url, prediction=result)
    session.add(new_check)
    session.commit()
    session.close()
    
    return jsonify({'url': url, 'prediction': result})

@app.route('/last_checks', methods=['GET'])
def last_checks():
    session = SessionLocal()
    checks = session.query(URLCheck).order_by(URLCheck.timestamp.desc()).limit(10).all()
    session.close()
    
    return jsonify([
        {'url': check.url, 'prediction': check.prediction, 'timestamp': check.timestamp.isoformat()}
        for check in checks
    ])

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
