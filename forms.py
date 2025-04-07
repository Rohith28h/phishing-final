"""
Forms Module
===========
Defines Flask-WTF forms for user authentication and URL checking.
Includes validation logic for registration, login, and URL submission.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, URLField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL
from models import User
import validators

class RegistrationForm(FlaskForm):
    """
    User registration form with validation for:
    - Username availability
    - Email availability
    - Password strength and matching
    """
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'), 
        Length(min=3, max=20, message='Username must be 3-20 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'), 
        Email(message='Invalid email format')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'), 
        Length(min=6, message='Password must be at least 6 characters')
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'), 
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Check if username is already taken"""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    def validate_email(self, email):
        """Check if email is already registered"""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

class LoginForm(FlaskForm):
    """
    User login form with basic validation
    """
    username = StringField('Username', validators=[
        DataRequired(message='Username is required')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    submit = SubmitField('Login')

class URLCheckForm(FlaskForm):
    """
    URL submission form for phishing detection
    Validates URL format before submission
    """
    url = URLField('Enter URL to check', validators=[
        DataRequired(message='URL is required'),
        URL(message='Please enter a valid URL (including http:// or https://)')
    ])
    submit = SubmitField('Check URL')
    
    def validate_url(self, url):
        """Additional URL validation using validators library"""
        if not validators.url(url.data):
            raise ValidationError('Invalid URL format. Please enter a valid URL (including http:// or https://)')
