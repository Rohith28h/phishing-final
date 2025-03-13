import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd
import os
import logging
import pickle

class EnsembleModel:
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.svm_model = SVC(probability=True, random_state=42)
        self.lr_model = LogisticRegression(random_state=42)
        self.is_trained = False
        self.feature_names = None
        
        # Try to load pre-trained models if they exist
        self._load_models()
    
    def _load_models(self):
        """Try to load pre-trained models or use default weights if not found"""
        try:
            # Load RF model
            with open('machine_learning/models/rf_model.pkl', 'rb') as f:
                self.rf_model = pickle.load(f)
                
            # Load SVM model
            with open('machine_learning/models/svm_model.pkl', 'rb') as f:
                self.svm_model = pickle.load(f)
                
            # Load LR model
            with open('machine_learning/models/lr_model.pkl', 'rb') as f:
                self.lr_model = pickle.load(f)
                
            self.is_trained = True
            logging.info("Successfully loaded pre-trained models")
        except FileNotFoundError:
            logging.warning("Model files not found. Using default weights.")
            # If models don't exist, use a basic default weighting
            self._train_with_defaults()
    
    def _train_with_defaults(self):
        """Train models with default dataset if no models are found"""
        try:
            # Try to load the phishing dataset
            data_path = 'attached_assets/phishcoop.csv'
            if os.path.exists(data_path):
                logging.info(f"Loading dataset from {data_path}")
                df = pd.read_csv(data_path)
                
                if df is not None and not df.empty:
                    # Extract features and target
                    X = df.drop(['id', 'Result'], axis=1, errors='ignore')
                    y = df['Result']
                    if y is not None:
                        # Store feature names
                        self.feature_names = X.columns.tolist()
                        
                        # Split the data
                        X_train, X_test, y_train, y_test = train_test_split(
                            X, y, test_size=0.25, random_state=42
                        )
                        
                        # Train the models
                        self.rf_model.fit(X_train, y_train)
                        self.svm_model.fit(X_train, y_train)
                        self.lr_model.fit(X_train, y_train)
                        
                        self.is_trained = True
                        logging.info("Models trained successfully with default dataset")
                        
                        # Create directory if it doesn't exist
                        os.makedirs('machine_learning/models', exist_ok=True)
                        
                        # Save the trained models
                        with open('machine_learning/models/rf_model.pkl', 'wb') as f:
                            pickle.dump(self.rf_model, f)
                        with open('machine_learning/models/svm_model.pkl', 'wb') as f:
                            pickle.dump(self.svm_model, f)
                        with open('machine_learning/models/lr_model.pkl', 'wb') as f:
                            pickle.dump(self.lr_model, f)
                    else:
                        logging.error("Target column 'Result' not found in dataset")
            else:
                logging.warning(f"Dataset not found at {data_path}")
        except Exception as e:
            logging.error(f"Error training models with defaults: {str(e)}")
            # Just continue with untrained models

    def _prepare_features(self, features_dict):
        """Prepare features for prediction"""
        # Convert dictionary to DataFrame with one row
        df = pd.DataFrame([features_dict])
        
        # If we have feature names from training, ensure consistent order
        if self.feature_names:
            # Add missing features as -1 (default value for missing feature)
            for feature in self.feature_names:
                if feature not in df.columns:
                    df[feature] = -1
            
            # Select only the features used during training, in the same order
            df = df[self.feature_names]
        
        return df

    def predict(self, features_dict):
        """
        Make a prediction with the ensemble model
        
        Args:
            features_dict: Dictionary of features extracted from URL
            
        Returns:
            tuple: (is_phishing (bool), confidence (float), feature_importance (dict))
        """
        # If models aren't trained yet, try to train them
        if not self.is_trained:
            self._train_with_defaults()
        
        # Extract and format features for prediction
        X = self._prepare_features(features_dict)
        
        # If training failed or we still don't have feature names, raise an error
        if not self.is_trained or not self.feature_names:
            # Use a simple fallback if models aren't trained
            # Return True if more negative features than positive
            negative_count = sum(1 for val in features_dict.values() if val < 0)
            positive_count = sum(1 for val in features_dict.values() if val > 0)
            is_phishing = negative_count > positive_count
            confidence = max(negative_count, positive_count) / (negative_count + positive_count) * 100
            
            return is_phishing, confidence, {}
        
        # Get predictions from each model
        rf_pred = self.rf_model.predict_proba(X)[0]
        svm_pred = self.svm_model.predict_proba(X)[0]
        lr_pred = self.lr_model.predict_proba(X)[0]
        
        # Combine predictions with weights (RF has highest accuracy, so give it more weight)
        # Weights: RF=0.5, SVM=0.3, LR=0.2
        ensemble_proba = 0.5 * rf_pred + 0.3 * svm_pred + 0.2 * lr_pred
        
        # Get the predicted class (0 = safe, 1 = phishing)
        # Note: The dataset has -1 for legitimate and 1 for phishing, 
        # but our output needs to be boolean
        prediction_idx = np.argmax(ensemble_proba)
        is_phishing = prediction_idx == 1  # True if prediction_idx is 1 (phishing)
        
        # Extract the confidence score (probability * 100 for percentage)
        confidence = ensemble_proba[prediction_idx] * 100
        
        # Get feature importance from Random Forest (most interpretable)
        if hasattr(self.rf_model, 'feature_importances_'):
            feature_importance = dict(zip(self.feature_names, self.rf_model.feature_importances_))
        else:
            feature_importance = {}
        
        return is_phishing, confidence, feature_importance
