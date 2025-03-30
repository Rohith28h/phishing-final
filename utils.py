import re
from urllib.parse import urlparse
import ipaddress
import socket
import validators
import logging
import requests
import trafilatura
import time
from bs4 import BeautifulSoup

def is_valid_url(url):
    """Validate if the URL has basic required structure for analysis"""
    try:
        # Parse URL and check for basic components
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        # Basic format validation (must have something that looks like a domain)
        domain = parsed.netloc
        if not domain or len(domain) < 3:  # At least 3 chars for domain
            return False

        # Allow more lenient validation for analysis
        # Just check if it has basic domain-like structure
        if '.' not in domain:
            return False

        return True
    except:
        return False

def is_ip_address(url):
    """Check if URL contains IP address"""
    try:
        parsed = urlparse(url).netloc
        ipaddress.ip_address(parsed)
        return 1
    except:
        return -1

def get_domain_age(domain):
    """Get domain age (simplified version)"""
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return -1
        
def is_whitelisted_domain(domain):
    """Check if domain is in the whitelist of known legitimate sites"""
    # Remove www prefix and get base domain
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # List of top trusted domains 
    whitelist = [
        # Global tech platforms
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 
        'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
        'apple.com', 'netflix.com', 'github.com', 'yahoo.com',
        'wikipedia.org', 'reddit.com', 'twitch.tv', 'ebay.com',
        'paypal.com', 'dropbox.com', 'spotify.com', 'adobe.com',
        
        # News and content
        'cnn.com', 'bbc.com', 'nytimes.com', 'wordpress.com',
        
        # Business and productivity
        'zoom.us', 'salesforce.com', 'slack.com', 'shopify.com',
        
        # Banking and financial institutions
        'onlinesbi.sbi', 'sbi.co.in', 'hdfc.com', 'icicibank.com', 'axisbank.com',
        'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
        'hsbc.com', 'barclays.co.uk', 'santander.com', 'tdbank.com'
    ]
    
    # Check if domain is in whitelist
    for trusted_domain in whitelist:
        if domain == trusted_domain or domain.endswith('.' + trusted_domain):
            logging.info(f"Domain {domain} is in trusted whitelist")
            return True
            
    return False

def analyze_website_content(url):
    """
    Analyze the content of a website to determine if it's likely a phishing site.
    Returns a dictionary of content-based features.
    """
    content_features = {
        'login_form_present': False,
        'password_field_present': False,
        'ssl_seal_present': False,
        'brand_mismatch': False,
        'security_indicators': False,
        'legitimate_links': False
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Fetch the website content with a timeout
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            # Get the main text content using trafilatura (better content extraction)
            try:
                text_content = trafilatura.extract(response.text)
            except:
                text_content = ""
                
            # Parse HTML using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for login forms
            forms = soup.find_all('form')
            if forms:
                content_features['login_form_present'] = True
                
            # Check for password fields    
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                content_features['password_field_present'] = True
                
            # Look for SSL seals or security badges
            security_images = ['secure', 'ssl', 'trust', 'verisign', 'norton', 'mcafee']
            for img in soup.find_all('img'):
                src = img.get('src', '').lower()
                alt = img.get('alt', '').lower()
                if any(term in src or term in alt for term in security_images):
                    content_features['ssl_seal_present'] = True
                    break
                    
            # Check if site has legitimate external links
            legit_domains = ['google.com', 'facebook.com', 'twitter.com', 'instagram.com']
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                if any(domain in href for domain in legit_domains):
                    content_features['legitimate_links'] = True
                    break
                    
            # Look for security indicators in text
            security_terms = ['secure', 'protected', 'verified', 'safe', 'trusted']
            if text_content and any(term in text_content.lower() for term in security_terms):
                content_features['security_indicators'] = True
                
            # Detect brand/domain mismatch (common in phishing)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check if known brand names appear in content but not in domain
            brand_terms = ['paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook', 'bank', 'google']
            
            if text_content:
                # Check if content contains a brand name not present in the domain
                mentioned_brands = [brand for brand in brand_terms if brand in text_content.lower()]
                for brand in mentioned_brands:
                    if brand not in domain:
                        content_features['brand_mismatch'] = True
                        break
                        
        logging.info(f"Content analysis for {url}: {content_features}")
        return content_features
        
    except Exception as e:
        logging.error(f"Error analyzing website content: {e}")
        return content_features

def extract_features(url):
    """Extract features from URL for phishing detection"""
    # First validate the URL has basic structure
    if not is_valid_url(url):
        raise ValueError("Invalid URL format. URL must include http:// or https:// and a domain name (e.g., http://example.com)")

    features = {}

    # Parse URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check whitelist first - if domain is whitelisted, set all features to indicate legitimacy
    if is_whitelisted_domain(domain):
        logging.info(f"URL {url} contains a whitelisted domain, treating as legitimate")
        
        # Initialize all features as legitimate (-1 typically indicates legitimate for most features)
        # This ensures well-known domains will almost always be classified as legitimate
        feature_list = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
            'Statistical_report'
        ]
        
        # Set all features to legitimate (-1)
        for feature in feature_list:
            features[feature] = -1
        
        # Set a few positive features for whitelisted domains
        features['SSLfinal_State'] = 1  # Most have HTTPS
        features['Domain_registeration_length'] = 1  # Most have long registration
        features['Google_Index'] = 1  # Most are indexed
        features['Page_Rank'] = 1  # Most have good rankings
        
        return features
    
    # Continue with normal feature extraction for non-whitelisted domains
    # Feature: having_IP_Address
    features['having_IP_Address'] = is_ip_address(url)

    # Feature: URL_Length
    features['URL_Length'] = 1 if len(url) > 54 else -1

    # Feature: Shortining_Service
    short_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com']
    features['Shortining_Service'] = 1 if any(service in url for service in short_services) else -1

    # Feature: having_At_Symbol
    features['having_At_Symbol'] = 1 if '@' in url else -1

    # Feature: double_slash_redirecting
    features['double_slash_redirecting'] = 1 if url.replace('https://', '').find('//') != -1 else -1

    # Feature: Prefix_Suffix
    features['Prefix_Suffix'] = 1 if '-' in domain else -1

    # Feature: having_Sub_Domain
    dots = domain.count('.')
    features['having_Sub_Domain'] = 1 if dots > 2 else (0 if dots == 2 else -1)

    # Feature: SSLfinal_State
    features['SSLfinal_State'] = 1 if url.startswith('https') else -1

    # Feature: Domain_registeration_length
    features['Domain_registeration_length'] = get_domain_age(domain)

    # Feature: Favicon
    features['Favicon'] = 1

    # Feature: port
    features['port'] = 1 if any(str(i) in domain for i in range(80, 8090)) else -1

    # Feature: HTTPS_token
    features['HTTPS_token'] = 1 if 'https' in domain else -1

    # Try to get real-time content features
    try:
        content_features = analyze_website_content(url)
        
        # Adjust features based on content analysis
        if content_features['login_form_present'] and content_features['brand_mismatch']:
            # This is a red flag for phishing
            features['Submitting_to_email'] = 1
            features['SFH'] = 1
        
        if content_features['password_field_present'] and not url.startswith('https'):
            # Another red flag - asking for password without HTTPS
            features['SSLfinal_State'] = 1
        
        if content_features['ssl_seal_present'] and not content_features['security_indicators']:
            # Sites with fake security indicators
            features['Redirect'] = 1
            
        if content_features['legitimate_links']:
            # Sites with legitimate external links are less likely to be phishing
            features['Links_pointing_to_page'] = -1
            
    except Exception as e:
        logging.error(f"Error in content analysis: {e}")
    
    # Additional features (simplified)
    for feature in ['Request_URL', 'URL_of_Anchor', 'Links_in_tags', 
                  'Abnormal_URL', 'on_mouseover', 'RightClick', 'popUpWidnow', 
                  'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank', 
                  'Google_Index', 'Statistical_report']:
        if feature not in features:
            features[feature] = -1

    return features