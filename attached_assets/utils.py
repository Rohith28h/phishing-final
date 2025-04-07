"""
URL Utility Module
=================
This module provides URL validation and feature extraction functions
for phishing detection. It analyzes URLs to extract security-relevant
features that can be used by machine learning models.
"""

import re
from urllib.parse import urlparse
import ipaddress
import socket
import validators

def is_valid_url(url):
    """
    Validate if URL has basic required structure for analysis
    Args:
        url: String containing URL to validate
    Returns:
        bool: True if URL has valid structure, False otherwise
    """
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
    """
    Check if URL contains IP address instead of domain name
    Args:
        url: String containing URL to check
    Returns:
        int: 1 if URL uses IP address, -1 otherwise
    """
    try:
        parsed = urlparse(url).netloc
        ipaddress.ip_address(parsed)  # Will raise ValueError if not IP
        return 1
    except:
        return -1

def get_domain_age(domain):
    """
    Simplified domain age check (checks if domain resolves)
    Args:
        domain: String containing domain name
    Returns:
        int: 1 if domain resolves, -1 otherwise
    """
    try:
        socket.gethostbyname(domain)  # Will raise socket.error if can't resolve
        return 1
    except:
        return -1

def extract_features(url):
    """
    Extract phishing detection features from URL
    Args:
        url: String containing URL to analyze
    Returns:
        dict: Dictionary of feature names to values
    Raises:
        ValueError: If URL format is invalid
    """
    # First validate the URL has basic structure
    if not is_valid_url(url):
        raise ValueError("Invalid URL format. URL must include http:// or https:// and a domain name (e.g., http://example.com)")

    features = {}

    # Parse URL components
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Feature: having_IP_Address (1 if URL uses IP address)
    features['having_IP_Address'] = is_ip_address(url)

    # Feature: URL_Length (1 if URL > 54 chars, -1 otherwise)
    features['URL_Length'] = 1 if len(url) > 54 else -1

    # Feature: Shortining_Service (1 if URL uses known shortening service)
    short_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com']
    features['Shortining_Service'] = 1 if any(service in url for service in short_services) else -1

    # Feature: having_At_Symbol (1 if '@' in URL)
    features['having_At_Symbol'] = 1 if '@' in url else -1

    # Feature: double_slash_redirecting (1 if URL has double slash after protocol)
    features['double_slash_redirecting'] = 1 if url.replace('https://', '').find('//') != -1 else -1

    # Feature: Prefix_Suffix (1 if domain contains hyphen)
    features['Prefix_Suffix'] = 1 if '-' in domain else -1

    # Feature: having_Sub_Domain (1 if >2 dots, 0 if 2 dots, -1 otherwise)
    dots = domain.count('.')
    features['having_Sub_Domain'] = 1 if dots > 2 else (0 if dots == 2 else -1)

    # Feature: SSLfinal_State (1 if HTTPS)
    features['SSLfinal_State'] = 1 if url.startswith('https') else -1

    # Feature: Domain_registeration_length (1 if domain resolves)
    features['Domain_registeration_length'] = get_domain_age(domain)

    # Feature: Favicon (default 1)
    features['Favicon'] = 1

    # Feature: port (1 if port number in domain)
    features['port'] = 1 if any(str(i) in domain for i in range(80, 8090)) else -1

    # Feature: HTTPS_token (1 if 'https' appears in domain)
    features['HTTPS_token'] = 1 if 'https' in domain else -1

    # Additional features (simplified implementation - defaults to -1)
    for feature in ['Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 
                   'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
                   'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord',
                   'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
                   'Statistical_report']:
        features[feature] = -1

    return features
