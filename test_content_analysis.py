"""
Test script for content-based phishing detection
This script tests the enhanced content analysis capabilities
"""
import requests
import json
import time
import argparse
from urllib.parse import urlparse

def test_content_analysis(url):
    """Test the content analysis functionality with a given URL"""
    print(f"Testing content analysis for URL: {url}")
    
    # Check if URL is in valid format
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print("Error: Invalid URL format. URL must include http:// or https:// and a domain name")
            return
    except:
        print("Error: Could not parse URL")
        return
    
    # Import analysis function directly from utils
    try:
        from utils import analyze_website_content
        
        print("\nRunning direct content analysis...")
        start_time = time.time()
        content_features = analyze_website_content(url)
        end_time = time.time()
        
        print(f"Analysis completed in {end_time - start_time:.2f} seconds")
        print("\nContent Analysis Results:")
        print("-" * 50)
        for feature, value in content_features.items():
            print(f"{feature:<25}: {value}")
            
        # Evaluate risk factors
        suspicious_count = 0
        if content_features.get('login_form_present') and content_features.get('brand_mismatch'):
            suspicious_count += 2
            print("\n[ALERT] Login form with brand mismatch detected - high risk indicator")
            
        if content_features.get('password_field_present') and not url.startswith('https'):
            suspicious_count += 2
            print("\n[ALERT] Password field without HTTPS detected - high risk indicator")
            
        if content_features.get('ssl_seal_present') and not content_features.get('security_indicators'):
            suspicious_count += 1
            print("\n[ALERT] Potential fake security seals detected")
            
        if suspicious_count >= 3:
            print("\n🔴 HIGH RISK: Multiple suspicious indicators found")
        elif suspicious_count > 0:
            print("\n🟠 MEDIUM RISK: Some suspicious indicators found")
        else:
            print("\n🟢 LOW RISK: No suspicious content indicators detected")
            
    except Exception as e:
        print(f"Error during content analysis: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test content-based phishing detection")
    parser.add_argument("url", help="URL to analyze for phishing content")
    args = parser.parse_args()
    
    test_content_analysis(args.url)