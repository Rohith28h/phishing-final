import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse
from forms import LoginForm, RegistrationForm, URLCheckForm
from models import User, initialize_model, predict_url
from utils import extract_features
from extensions import db, login_manager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET") or 'your_secret_key_here'
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    return app

app = create_app()

# Initialize ML model lazily
rf_model = None

def get_model():
    global rf_model
    if rf_model is None:
        try:
            logger.info("Initializing ML model...")
            rf_model = initialize_model()
            logger.info("ML model initialization completed")
        except Exception as e:
            logger.error(f"Error initializing model: {str(e)}")
            raise
    return rf_model

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    logger.debug(f"Attempting to log in user: {form.username.data}")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if User.query.filter_by(email=form.email.data).first():
        flash('Email address already exists. Please use a different email.')
        return redirect(url_for('register'))
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/check-url', methods=['GET', 'POST'])
@login_required
def check_url():
    form = URLCheckForm()
    if form.validate_on_submit():
        try:
            url = form.url.data

            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            # Try to extract features, this will raise ValueError for invalid URLs
            features = extract_features(url)

            # Get or initialize model
            model = get_model()

            prediction, probability = predict_url(model, features)

            result = {
                'url': url,
                'is_phishing': prediction == 1,
                'features': features,
                'risk_score': probability,  # Assuming probability is the risk score
                'classification_confidence': prediction  # Assuming prediction holds confidence
            }

            if result['is_phishing']:
                return render_template('phishing_warning.html', result=result)

            return render_template('result.html', result=result)  # This line can be kept if needed for non-phishing URLs
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('check_url'))
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            flash("An error occurred while analyzing the URL. Please try again.")
            return redirect(url_for('check_url'))

    return render_template('check_url.html', form=form)

# Create database tables
with app.app_context():
    db.create_all()
