"""
Phishing Detection Web Application

This Flask application provides a web interface for detecting phishing websites using:
- Machine learning models (ensemble approach)
- URL feature analysis
- Website content analysis
- Whitelist/blacklist checking

Key Features:
- User authentication (login/registration)
- URL analysis interface
- API endpoint for external services
- Database storage of analysis results
- Real-time content analysis
"""
import os
import logging
from urllib.parse import urlparse
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import DeclarativeBase
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# =============================================
# Application Initialization and Configuration
# =============================================

# Initialize Flask application and extensions
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Application Configuration
# ------------------------
# Note: In production, these should come from environment variables
app.secret_key = os.environ.get("SESSION_SECRET", "dev-key-for-testing")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Custom Jinja Filters
# -------------------
# These filters are available in all templates
@app.template_filter('file_exists')
def file_exists(filename):
    """Check if a file exists in the static folder"""
    return os.path.isfile(os.path.join(app.static_folder, filename))

# Initialize Flask Extensions
# --------------------------
# These must be initialized after app creation
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Import Models and Utilities
# --------------------------
# Imported after db initialization to avoid circular imports
# Import database models (defined in models.py)
from models import User, URLAnalysis  # User handles authentication, URLAnalysis stores scan results

# Import WTForms classes (defined in forms.py)
from forms import LoginForm, RegistrationForm, URLCheckForm  # Form definitions for user input validation

# Import utility functions (defined in utils.py)
from utils import (
    is_valid_url,          # Validates URL format
    extract_features,      # Extracts ML features from URL (used by machine_learning/feature_processor.py)
    is_whitelisted_domain, # Checks against known safe domains 
    analyze_website_content # Performs content analysis (uses machine_learning/models/)
)

# Import ML model (defined in machine_learning/ensemble_model.py)
from machine_learning.ensemble_model import EnsembleModel  # Combines predictions from multiple ML models

# Machine Learning Model Initialization
# ------------------------------------
# The ensemble model combines multiple ML approaches for better accuracy
phishing_detector = EnsembleModel()

# ===========================
# Authentication Routes
# ===========================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ===========================
# Main Application Routes
# ===========================

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        try:
            db.session.commit()
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error registering user: {e}")
            flash('Registration failed. Username or email may already be in use.', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# =========================================
# URL Analysis and Phishing Detection
# =========================================

@app.route('/check_url', methods=['GET', 'POST'])
@login_required
def check_url():
    """
    Main phishing detection endpoint that:
    1. Validates URL via utils.is_valid_url()
    2. Checks whitelist via utils.is_whitelisted_domain() 
    3. Extracts features via utils.extract_features()
    4. Gets ML prediction via EnsembleModel.predict()
    5. Performs content analysis via utils.analyze_website_content()
    6. Stores results in URLAnalysis model
    7. Renders appropriate template (templates/phishing_warning.html or templates/result.html)
    """
    form = URLCheckForm()
    if form.validate_on_submit():
        url = form.url.data
        try:
            # Parse URL using urllib.parse - extracts components like domain, path, etc.
            parsed_url = urlparse(url)  # Returns ParseResult object
            domain = parsed_url.netloc  # Get just the domain portion (e.g. "example.com")
            
            # Check if domain is in whitelist before full processing
            domain_whitelisted = is_whitelisted_domain(domain)
            if domain_whitelisted:
                app.logger.info(f"URL {url} contains a whitelisted domain, skipping ML prediction")
                is_phishing = False
                probability = 0.1  # Very low probability for whitelisted domains
                features = extract_features(url)  # Still need features for storage
            else:
                # Extract features and make prediction using ML model
                # Extract URL features using utility function (links to feature_processor.py)
                features = extract_features(url)  # Returns dict of features for ML model
                
                # Get prediction from ensemble model (combines multiple ML models)
                is_phishing, probability, feature_importance = phishing_detector.predict(features)
                # Returns: 
                # - is_phishing (bool): Final classification
                # - probability (float): Confidence score (0-1)
                # - feature_importance: Which features contributed most to decision
                
                # Perform additional content analysis for non-whitelisted domains
                # This can help catch phishing sites that might slip through ML detection
                content_features = analyze_website_content(url)
                app.logger.info(f"Content analysis for {url}: {content_features}")
                
                # If ML says it's not phishing but content analysis shows suspicious indicators,
                # adjust the probability and potentially flag as phishing
                if not is_phishing:
                    suspicious_indicators = 0
                    
                    # Check for highly suspicious combinations
                    if content_features['login_form_present'] and content_features['brand_mismatch']:
                        suspicious_indicators += 2
                        app.logger.warning(f"Suspicious: Login form with brand mismatch on {url}")
                    
                    if content_features['password_field_present'] and url and not url.lower().startswith('https'):
                        suspicious_indicators += 2
                        app.logger.warning(f"Suspicious: Password field without HTTPS on {url}")
                        
                    if content_features['ssl_seal_present'] and not content_features['security_indicators']:
                        suspicious_indicators += 1
                        app.logger.warning(f"Suspicious: SSL seal without proper security indicators on {url}")
                    
                    # Only override if multiple suspicious indicators are found
                    if suspicious_indicators >= 3:
                        app.logger.warning(f"Content analysis override: Marking {url} as phishing based on content indicators")
                        is_phishing = True
                        probability = max(probability, 0.75)  # At least 75% confidence
                    elif suspicious_indicators > 0:
                        # Increase probability but don't necessarily mark as phishing
                        probability = max(probability, 0.5)  # At least 50% confidence
            
            # Store analysis result
            analysis = URLAnalysis(
                url=url,
                user_id=current_user.id,
                is_phishing=is_phishing,
                confidence_score=probability,
                features=str(features)
            )
            db.session.add(analysis)
            db.session.commit()
            
            # Get real-time content analysis for result display
            try:
                content_analysis = analyze_website_content(url)
            except Exception as e:
                app.logger.error(f"Error in content analysis: {e}")
                content_analysis = {}
            
            # Prepare result for template
            result = {
                'url': url,
                'is_phishing': is_phishing,
                'classification_confidence': f"{probability*100:.2f}%" if probability <= 1 else f"{probability:.2f}%",
                'risk_score': "High Risk" if is_phishing else "Low Risk",
                'features': features,
                'whitelisted': domain_whitelisted,
                'content_analysis': content_analysis,
                'analysis_time': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Different templates for phishing vs. safe sites
            if is_phishing:
                return render_template('phishing_warning.html', result=result)
            else:
                return render_template('result.html', result=result)
        
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            app.logger.error(f"Error analyzing URL: {e}")
            flash('An error occurred while analyzing the URL. Please try again.', 'danger')
    
    return render_template('check_url.html', form=form)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    url = request.form.get('url')
    if not url:
        return render_template('index.html', error='Please enter a URL')
    
    try:
        if not is_valid_url(url):
            return render_template('index.html', error='Invalid URL format. Please enter a valid URL.')
        
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check if domain is in whitelist before full processing
        domain_whitelisted = is_whitelisted_domain(domain)
        if domain_whitelisted:
            app.logger.info(f"URL {url} contains a whitelisted domain, skipping ML prediction")
            is_phishing = False
            probability = 0.1  # Very low probability for whitelisted domains
            features = extract_features(url)  # Still need features for storage
        else:
            # Extract features and make prediction using ML model
            features = extract_features(url)
            is_phishing, probability, feature_importance = phishing_detector.predict(features)
            
            # Perform additional content analysis for non-whitelisted domains
            # This can help catch phishing sites that might slip through ML detection
            content_features = analyze_website_content(url)
            app.logger.info(f"Content analysis for {url}: {content_features}")
            
            # If ML says it's not phishing but content analysis shows suspicious indicators,
            # adjust the probability and potentially flag as phishing
            if not is_phishing:
                suspicious_indicators = 0
                
                # Check for highly suspicious combinations
                if content_features['login_form_present'] and content_features['brand_mismatch']:
                    suspicious_indicators += 2
                    app.logger.warning(f"Suspicious: Login form with brand mismatch on {url}")
                
                if content_features['password_field_present'] and url and not url.lower().startswith('https'):
                    suspicious_indicators += 2
                    app.logger.warning(f"Suspicious: Password field without HTTPS on {url}")
                    
                if content_features['ssl_seal_present'] and not content_features['security_indicators']:
                    suspicious_indicators += 1
                    app.logger.warning(f"Suspicious: SSL seal without proper security indicators on {url}")
                
                # Only override if multiple suspicious indicators are found
                if suspicious_indicators >= 3:
                    app.logger.warning(f"Content analysis override: Marking {url} as phishing based on content indicators")
                    is_phishing = True
                    probability = max(probability, 0.75)  # At least 75% confidence
                elif suspicious_indicators > 0:
                    # Increase probability but don't necessarily mark as phishing
                    probability = max(probability, 0.5)  # At least 50% confidence 
        
        # Store analysis result
        analysis = URLAnalysis(
            url=url,
            user_id=current_user.id,
            is_phishing=is_phishing,
            confidence_score=probability,
            features=str(features)
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Get real-time content analysis for result display
        try:
            content_analysis = analyze_website_content(url)
        except Exception as e:
            app.logger.error(f"Error in content analysis: {e}")
            content_analysis = {}
        
        # Prepare result for template
        result = {
            'url': url,
            'is_phishing': is_phishing,
            'classification_confidence': f"{probability*100:.2f}%" if probability <= 1 else f"{probability:.2f}%",
            'risk_score': "High Risk" if is_phishing else "Low Risk",
            'features': features,
            'whitelisted': domain_whitelisted,
            'content_analysis': content_analysis,
            'analysis_time': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Different templates for phishing vs. safe sites
        if is_phishing:
            return render_template('phishing_warning.html', result=result)
        else:
            return render_template('result.html', result=result)
    
    except ValueError as e:
        return render_template('index.html', error=str(e))
    except Exception as e:
        app.logger.error(f"Error analyzing URL: {e}")
        return render_template('index.html', error='An error occurred while analyzing the URL. Please try again.')

# ===========================
# Database Management
# ===========================

# Create all database tables
# Should be called at application startup
def create_tables():
    with app.app_context():
        db.create_all()

# ===========================
# API Endpoints
# ===========================

# JSON API for external service integration
# Uses same detection logic as web interface
@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'error': 'Missing URL parameter',
            'status': 'error'
        }), 400
    
    url = data['url']
    
    try:
        if not is_valid_url(url):
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error'
            }), 400
        
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check whitelist first
        domain_whitelisted = is_whitelisted_domain(domain)
        if domain_whitelisted:
            app.logger.info(f"API: URL {url} contains a whitelisted domain, skipping ML prediction")
            is_phishing = False
            probability = 0.05
            features = extract_features(url)
            content_features = {}
        else:
            # Extract features and run ML prediction
            features = extract_features(url)
            is_phishing, probability, feature_importance = phishing_detector.predict(features)
            
            # Run content analysis for more accurate results
            content_features = analyze_website_content(url)
            
            # Potentially override ML result based on content analysis
            if not is_phishing:
                suspicious_indicators = 0
                
                if content_features['login_form_present'] and content_features['brand_mismatch']:
                    suspicious_indicators += 2
                
                if content_features['password_field_present'] and url and not url.lower().startswith('https'):
                    suspicious_indicators += 2
                    
                if content_features['ssl_seal_present'] and not content_features['security_indicators']:
                    suspicious_indicators += 1
                
                if suspicious_indicators >= 3:
                    is_phishing = True
                    probability = max(probability, 0.8)
                elif suspicious_indicators > 0:
                    probability = max(probability, 0.5)
        
        # Store the analysis in database
        analysis = URLAnalysis(
            url=url,
            user_id=current_user.id,
            is_phishing=is_phishing,
            confidence_score=probability,
            features=str(features)
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Return structured API response
        result = {
            'url': url,
            'is_phishing': is_phishing,
            'confidence': round(probability * 100, 2) if probability <= 1 else round(probability, 2),
            'risk_level': 'high' if is_phishing else 'low',
            'whitelisted': domain_whitelisted,
            'analysis_time': datetime.utcnow().isoformat(),
            'content_analysis': content_features
        }
        
        return jsonify({
            'status': 'success',
            'result': result
        })
        
    except Exception as e:
        app.logger.error(f"API error analyzing URL: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

# ===========================
# Application Startup
# ===========================

# Initialize database tables
create_tables()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
