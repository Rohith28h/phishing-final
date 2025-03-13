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

# Initialize app
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get("SESSION_SECRET", "dev-key-for-testing")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///site.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Import after initializing db to avoid circular imports
from models import User, URLAnalysis
from forms import LoginForm, RegistrationForm, URLCheckForm
from utils import is_valid_url, extract_features, is_whitelisted_domain, analyze_website_content
from machine_learning.ensemble_model import EnsembleModel

# Initialize machine learning model
phishing_detector = EnsembleModel()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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

@app.route('/check_url', methods=['GET', 'POST'])
@login_required
def check_url():
    form = URLCheckForm()
    if form.validate_on_submit():
        url = form.url.data
        try:
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
                    
                    if content_features['password_field_present'] and not url.startswith('https'):
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
                'classification_confidence': f"{probability*100:.2f}%",
                'risk_score': "High Risk" if is_phishing else "Low Risk",
                'features': features,
                'whitelisted': domain_whitelisted,
                'content_analysis': content_analysis
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
                
                if content_features['password_field_present'] and not url.startswith('https'):
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
            'classification_confidence': f"{probability*100:.2f}%",
            'risk_score': "High Risk" if is_phishing else "Low Risk",
            'features': features,
            'whitelisted': domain_whitelisted,
            'content_analysis': content_analysis
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

# Create database tables
def create_tables():
    with app.app_context():
        db.create_all()

# API endpoint for external service integration
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
                
                if content_features['password_field_present'] and not url.startswith('https'):
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
            'confidence': round(probability * 100, 2),
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

# Create tables at startup
create_tables()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
