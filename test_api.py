"""
Test script for the phishing detection API
"""
import requests
import json
import argparse
import time
from getpass import getpass

def test_api(url, api_url, username, password):
    """Test the phishing detection API with a given URL"""
    print(f"Testing phishing detection API for URL: {url}")
    
    # First, authenticate to get a session
    session = requests.Session()
    
    # Get the login page to retrieve CSRF token
    login_resp = session.get(f"{api_url}/login")
    
    # Perform login if authentication is required
    print(f"Logging in as {username}...")
    login_data = {
        'username': username,
        'password': password,
        'submit': 'Login'
    }
    login_resp = session.post(f"{api_url}/login", data=login_data, allow_redirects=True)
    
    if "Login failed" in login_resp.text:
        print("Login failed. Check credentials and try again.")
        return
    
    print("Login successful. Making API request...")
    
    # Make API request
    start_time = time.time()
    
    api_data = {
        'url': url
    }
    
    try:
        response = session.post(
            f"{api_url}/api/analyze", 
            json=api_data,
            headers={'Content-Type': 'application/json'}
        )
        
        end_time = time.time()
        
        print(f"API request completed in {end_time - start_time:.2f} seconds")
        
        if response.status_code == 200:
            result = response.json()
            
            print("\nAPI Response:")
            print("-" * 50)
            print(json.dumps(result, indent=2))
            
            # Extract key information
            if result['status'] == 'success':
                phishing_result = result['result']
                
                print("\nSummary:")
                print(f"URL: {phishing_result['url']}")
                print(f"Phishing Detection: {'POSITIVE' if phishing_result['is_phishing'] else 'NEGATIVE'}")
                print(f"Confidence: {phishing_result['confidence']}%")
                print(f"Risk Level: {phishing_result['risk_level'].upper()}")
                
                if 'content_analysis' in phishing_result and phishing_result['content_analysis']:
                    content = phishing_result['content_analysis']
                    print("\nContent Analysis:")
                    
                    if content.get('login_form_present') and content.get('brand_mismatch'):
                        print("⚠️ WARNING: Login form with brand mismatch detected")
                    
                    if content.get('password_field_present') and not url.startswith('https'):
                        print("⚠️ WARNING: Password field without HTTPS detected")
            else:
                print(f"API Error: {result.get('error', 'Unknown error')}")
        else:
            print(f"API request failed with status code: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"Error during API request: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test phishing detection API")
    parser.add_argument("url", help="URL to analyze for phishing")
    parser.add_argument("--api", default="http://localhost:5000", help="API base URL")
    parser.add_argument("--username", default="admin", help="Username for authentication")
    
    args = parser.parse_args()
    
    # Get password securely
    password = getpass("Enter password: ")
    
    test_api(args.url, args.api, args.username, password)