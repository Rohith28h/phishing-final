import os
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def initialize_model():
    """Initialize and train multiple models using the phishing dataset"""
    try:
        logging.info("Starting model initialization...")

        # Load the dataset using relative path from root directory
        dataset_path = 'attached_assets/phishcoop.csv'
        logging.info(f"Loading dataset from: {dataset_path}")

        df = pd.read_csv(dataset_path)
        logging.info(f"Dataset loaded successfully. Shape: {df.shape}")

        # Validate dataset labels
        unique_labels = df['Result'].unique()
        logging.info(f"Unique class labels in dataset: {unique_labels}")
        if not all(label in [-1, 1] for label in unique_labels):
            raise ValueError("Dataset contains unexpected class labels. Expected -1 and 1.")

        # Separate features and target
        X = df.drop(['id', 'Result'], axis=1)
        y = df['Result']

        # Split the data with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        logging.info("Data split completed")

        # Initialize and fit scaler
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        logging.info("Data scaling completed")

        # Initialize individual models with reduced parameters
        rf_model = RandomForestClassifier(
            n_estimators=100,  # Reduced for initial stability
            max_depth=10,      # Reduced for initial stability
            min_samples_split=4,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight={-1: 1, 1: 3},  # Give more weight to phishing class (1)
            random_state=42,
            n_jobs=-1
        )

        svm_model = SVC(
            kernel='rbf',
            C=10,
            gamma='scale',
            probability=True,
            class_weight={-1: 1, 1: 3},  # Give more weight to phishing class (1)
            random_state=42
        )

        lr_model = LogisticRegression(
            C=1.0,
            class_weight={-1: 1, 1: 3},  # Give more weight to phishing class (1)
            random_state=42,
            max_iter=1000,
            n_jobs=-1
        )

        # Check the actual unique values in y_train
        unique_classes = np.unique(y_train)
        logging.info(f"Unique classes in training data: {unique_classes}")
        
        # Adjust class weights based on actual classes present
        class_weights = {}
        for cls in unique_classes:
            class_weights[cls] = 3 if cls == 1 else 1
            
        # Update model class weights
        rf_model.class_weight = class_weights
        svm_model.class_weight = class_weights
        lr_model.class_weight = class_weights
        
        # Train individual models
        logging.info("Training Random Forest model...")
        rf_model.fit(X_train_scaled, y_train)
        logging.info("Random Forest model training completed")

        logging.info("Training SVM model...")
        svm_model.fit(X_train_scaled, y_train)
        logging.info("SVM model training completed")

        logging.info("Training Logistic Regression model...")
        lr_model.fit(X_train_scaled, y_train)
        logging.info("Logistic Regression model training completed")

        # Create new instances of models for ensemble to avoid class_weight issues
        rf_ensemble = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1
        )
        
        svm_ensemble = SVC(
            kernel='rbf',
            C=10,
            gamma='scale',
            probability=True,
            random_state=42
        )
        
        lr_ensemble = LogisticRegression(
            C=1.0,
            random_state=42,
            max_iter=1000,
            n_jobs=-1
        )
        
        # Train these models without class_weight
        rf_ensemble.fit(X_train_scaled, y_train)
        svm_ensemble.fit(X_train_scaled, y_train)
        lr_ensemble.fit(X_train_scaled, y_train)
        
        # Create voting classifier with weighted voting
        ensemble_model = VotingClassifier(
            estimators=[
                ('rf', rf_ensemble),
                ('svm', svm_ensemble),
                ('lr', lr_ensemble)
            ],
            voting='soft',
            weights=[3, 2, 1]  # Give higher weight to Random Forest predictions
        )

        # Train the ensemble model
        logging.info("Training ensemble model...")
        ensemble_model.fit(X_train_scaled, y_train)
        logging.info("Ensemble model training completed")

        # Save scaler as a global variable for predictions
        global feature_scaler
        feature_scaler = scaler

        # Calculate and print accuracy for each model
        X_test_scaled = scaler.transform(X_test)
        for name, model in [('Random Forest', rf_model), ('SVM', svm_model), 
                          ('Logistic Regression', lr_model), ('Ensemble', ensemble_model)]:
            accuracy = model.score(X_test_scaled, y_test)
            logging.info(f"{name} accuracy: {accuracy:.2f}")

        return ensemble_model
    except Exception as e:
        logging.error(f"Error initializing model: {str(e)}")
        raise

def predict_url(model, features):
    """Make prediction for a URL using the ensemble model"""
    try:
        # Convert features dictionary to DataFrame with matching columns
        features_df = pd.DataFrame([features])

        # Scale features
        features_scaled = feature_scaler.transform(features_df)

        # Make prediction using the ensemble model
        probabilities = model.predict_proba(features_scaled)[0]

        # Get phishing probability (class 1)
        phishing_prob = probabilities[1]

        # Adjust threshold for more aggressive phishing detection
        # For URLs with suspicious patterns, lower the threshold
        threshold = 0.3  # Lower threshold to catch more potential phishing

        if phishing_prob > threshold:
            prediction = 1  # Phishing
            probability = phishing_prob
        else:
            prediction = -1  # Safe
            probability = 1 - phishing_prob  # Probability of being safe

        logging.info(f"Prediction: {prediction}, Phishing Probability: {phishing_prob * 100:.2f}%")
        return prediction, probability * 100  # Return probability as percentage
    except Exception as e:
        logging.error(f"Error making prediction: {str(e)}")
        raise