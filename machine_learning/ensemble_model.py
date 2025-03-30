import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectFromModel
import pandas as pd
import os
import logging
import pickle
import matplotlib.pyplot as plt
import seaborn as sns

class EnsembleModel:
    def __init__(self):
        # Improved Random Forest with more estimators and better hyperparameters
        self.rf_model = RandomForestClassifier(
            n_estimators=200, 
            max_depth=None,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            class_weight='balanced',
            random_state=42
        )
        
        # SVM with optimized parameters
        self.svm_model = SVC(
            C=10.0,
            kernel='rbf',
            gamma='scale',
            probability=True,
            class_weight='balanced',
            random_state=42
        )
        
        # Enhanced logistic regression
        self.lr_model = LogisticRegression(
            C=1.0,
            penalty='l2',
            solver='liblinear',
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        )
        
        # New model: Neural Network
        self.nn_model = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size='auto',
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        # New model: Gradient Boosting
        self.gb_model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=5,
            min_samples_split=5,
            min_samples_leaf=2,
            subsample=0.8,
            random_state=42
        )
        
        self.is_trained = False
        self.feature_names = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.model_weights = {
            'rf': 0.3,
            'svm': 0.2,
            'lr': 0.1,
            'nn': 0.2,
            'gb': 0.2
        }
        
        # Performance metrics
        self.performance_metrics = {
            'accuracy': 0,
            'precision': 0,
            'recall': 0,
            'f1': 0
        }
        
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
                        
                        # Apply feature scaling
                        self.scaler.fit(X_train)
                        X_train_scaled = self.scaler.transform(X_train)
                        X_test_scaled = self.scaler.transform(X_test)
                        
                        # Feature selection using Random Forest
                        self.feature_selector = SelectFromModel(RandomForestClassifier(n_estimators=100, random_state=42), 
                                                               threshold="median")
                        self.feature_selector.fit(X_train_scaled, y_train)
                        
                        # Get selected feature mask and indices
                        feature_mask = self.feature_selector.get_support()
                        selected_features = [feature for i, feature in enumerate(self.feature_names) if feature_mask[i]]
                        logging.info(f"Selected {len(selected_features)} important features out of {len(self.feature_names)}")
                        
                        # Update feature names to only include selected features
                        self.feature_names = selected_features
                        
                        # Apply feature selection
                        X_train_selected = self.feature_selector.transform(X_train_scaled)
                        X_test_selected = self.feature_selector.transform(X_test_scaled)
                        
                        # Train all models
                        logging.info("Training Random Forest model...")
                        self.rf_model.fit(X_train_selected, y_train)
                        
                        logging.info("Training SVM model...")
                        self.svm_model.fit(X_train_selected, y_train)
                        
                        logging.info("Training Logistic Regression model...")
                        self.lr_model.fit(X_train_selected, y_train)
                        
                        logging.info("Training Neural Network model...")
                        self.nn_model.fit(X_train_selected, y_train)
                        
                        logging.info("Training Gradient Boosting model...")
                        self.gb_model.fit(X_train_selected, y_train)
                        
                        # Evaluate models on test set
                        rf_preds = self.rf_model.predict(X_test_selected)
                        svm_preds = self.svm_model.predict(X_test_selected)
                        lr_preds = self.lr_model.predict(X_test_selected)
                        nn_preds = self.nn_model.predict(X_test_selected)
                        gb_preds = self.gb_model.predict(X_test_selected)
                        
                        # Calculate ensemble predictions
                        ensemble_preds = np.zeros_like(rf_preds, dtype=float)
                        ensemble_preds += self.model_weights['rf'] * rf_preds
                        ensemble_preds += self.model_weights['svm'] * svm_preds
                        ensemble_preds += self.model_weights['lr'] * lr_preds
                        ensemble_preds += self.model_weights['nn'] * nn_preds
                        ensemble_preds += self.model_weights['gb'] * gb_preds
                        
                        # Convert to binary predictions
                        binary_preds = (ensemble_preds > 0.5).astype(int)
                        
                        # Calculate performance metrics
                        self.performance_metrics['accuracy'] = accuracy_score(y_test, binary_preds)
                        self.performance_metrics['precision'] = precision_score(y_test, binary_preds, zero_division=0)
                        self.performance_metrics['recall'] = recall_score(y_test, binary_preds, zero_division=0)
                        self.performance_metrics['f1'] = f1_score(y_test, binary_preds, zero_division=0)
                        
                        logging.info(f"Ensemble model performance: Accuracy={self.performance_metrics['accuracy']:.4f}, "
                                   f"Precision={self.performance_metrics['precision']:.4f}, "
                                   f"Recall={self.performance_metrics['recall']:.4f}, "
                                   f"F1={self.performance_metrics['f1']:.4f}")
                        
                        # Generate feature importance chart
                        self._generate_feature_importance_chart()
                        
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
                        with open('machine_learning/models/nn_model.pkl', 'wb') as f:
                            pickle.dump(self.nn_model, f)
                        with open('machine_learning/models/gb_model.pkl', 'wb') as f:
                            pickle.dump(self.gb_model, f)
                        
                        # Save the scaler and feature selector
                        with open('machine_learning/models/scaler.pkl', 'wb') as f:
                            pickle.dump(self.scaler, f)
                        with open('machine_learning/models/feature_selector.pkl', 'wb') as f:
                            pickle.dump(self.feature_selector, f)
                    else:
                        logging.error("Target column 'Result' not found in dataset")
            else:
                logging.warning(f"Dataset not found at {data_path}")
        except Exception as e:
            logging.error(f"Error training models with defaults: {str(e)}")
            # Just continue with untrained models
            
    def _generate_feature_importance_chart(self):
        """Generate and save feature importance chart"""
        try:
            # Create the static directory if it doesn't exist
            os.makedirs('static/img', exist_ok=True)
            
            # Use Random Forest feature importances
            if hasattr(self.rf_model, 'feature_importances_') and self.feature_names:
                # Get top 10 features by importance
                importances = self.rf_model.feature_importances_
                indices = np.argsort(importances)[::-1][:10]  # Top 10 features
                
                plt.figure(figsize=(10, 6))
                sns.barplot(x=importances[indices], y=[self.feature_names[i] for i in indices])
                plt.title('Top 10 Feature Importance for Phishing Detection')
                plt.xlabel('Relative Importance')
                plt.tight_layout()
                plt.savefig('static/img/feature_importance.png')
                plt.close()
                
                logging.info("Feature importance chart saved to static/img/feature_importance.png")
                
                # Create pie chart of model weights
                plt.figure(figsize=(8, 8))
                plt.pie(list(self.model_weights.values()), labels=list(self.model_weights.keys()), 
                       autopct='%1.1f%%', startangle=90)
                plt.axis('equal')
                plt.title('Model Weights in Ensemble')
                plt.savefig('static/img/model_weights.png')
                plt.close()
                
                logging.info("Model weights chart saved to static/img/model_weights.png")
        except Exception as e:
            logging.error(f"Error generating feature importance chart: {e}")
            # Continue without the chart

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
        Make a prediction with the enhanced ensemble model
        
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
        
        # If training failed or we still don't have feature names, use a fallback
        if not self.is_trained or not self.feature_names:
            # Use a simple fallback if models aren't trained
            # Return True if more negative features than positive
            negative_count = sum(1 for val in features_dict.values() if val < 0)
            positive_count = sum(1 for val in features_dict.values() if val > 0)
            is_phishing = negative_count > positive_count
            confidence = max(negative_count, positive_count) / (negative_count + positive_count) * 100
            
            return is_phishing, confidence, {}
        
        try:
            # Apply scaling and feature selection if available
            if hasattr(self, 'scaler') and self.scaler is not None:
                X_scaled = self.scaler.transform(X)
                if hasattr(self, 'feature_selector') and self.feature_selector is not None:
                    X_processed = self.feature_selector.transform(X_scaled)
                else:
                    X_processed = X_scaled
            else:
                X_processed = X
                
            # Get predictions from each model
            rf_pred = self.rf_model.predict_proba(X_processed)[0]
            svm_pred = self.svm_model.predict_proba(X_processed)[0]
            lr_pred = self.lr_model.predict_proba(X_processed)[0]
            
            # Get predictions from new models if they exist
            if hasattr(self, 'nn_model') and self.nn_model is not None:
                nn_pred = self.nn_model.predict_proba(X_processed)[0]
            else:
                nn_pred = rf_pred  # Fallback to RF if NN not available
                
            if hasattr(self, 'gb_model') and self.gb_model is not None:
                gb_pred = self.gb_model.predict_proba(X_processed)[0]
            else:
                gb_pred = rf_pred  # Fallback to RF if GB not available
            
            # Combine predictions with optimized weights
            ensemble_proba = (
                self.model_weights['rf'] * rf_pred + 
                self.model_weights['svm'] * svm_pred + 
                self.model_weights['lr'] * lr_pred +
                self.model_weights['nn'] * nn_pred +
                self.model_weights['gb'] * gb_pred
            )
            
            # Get the predicted class (0 = safe, 1 = phishing)
            # Note: The dataset has -1 for legitimate and 1 for phishing, 
            # but our output needs to be boolean
            prediction_idx = np.argmax(ensemble_proba)
            is_phishing = prediction_idx == 1  # True if prediction_idx is 1 (phishing)
            
            # Extract the confidence score (probability * 100 for percentage)
            confidence = ensemble_proba[prediction_idx] * 100
            
            # Get feature importance from Random Forest (most interpretable)
            if hasattr(self.rf_model, 'feature_importances_'):
                # Get the top 10 most important features for display
                importances = self.rf_model.feature_importances_
                indices = np.argsort(importances)[::-1][:10]  # Top 10 features
                
                # Create dictionary of feature importances (all features)
                feature_importance = dict(zip(self.feature_names, self.rf_model.feature_importances_))
                
                # Create dictionary for top 10 features
                top_feature_importance = {self.feature_names[i]: importances[i] for i in indices}
                
                # Return all importances but mark top 10
                feature_importance['top_features'] = top_feature_importance
            else:
                feature_importance = {}
            
            # Add performance metrics to the output if available
            if hasattr(self, 'performance_metrics'):
                feature_importance['model_performance'] = self.performance_metrics
            
            return is_phishing, confidence, feature_importance
            
        except Exception as e:
            # Fallback to simpler prediction in case of error
            logging.error(f"Error in ensemble prediction: {str(e)}")
            
            # Use only Random Forest if it's trained
            try:
                if self.is_trained and hasattr(self.rf_model, 'predict_proba'):
                    # Use only Random Forest for prediction
                    rf_pred = self.rf_model.predict_proba(X)[0]
                    prediction_idx = np.argmax(rf_pred)
                    is_phishing = prediction_idx == 1
                    confidence = rf_pred[prediction_idx] * 100
                    
                    return is_phishing, confidence, {}
            except:
                pass
                
            # Ultimate fallback - rule-based approach
            negative_count = sum(1 for val in features_dict.values() if val < 0)
            positive_count = sum(1 for val in features_dict.values() if val > 0)
            is_phishing = negative_count > positive_count
            confidence = max(negative_count, positive_count) / (negative_count + positive_count) * 100
            
            return is_phishing, confidence, {}
