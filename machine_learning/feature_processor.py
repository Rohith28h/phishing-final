"""
Feature Processor Module
=======================
This module handles feature preprocessing for phishing detection models.
It standardizes numerical features and handles missing values before model training/prediction.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

class FeatureProcessor:
    """
    A feature processing pipeline that:
    - Standardizes numerical features using StandardScaler
    - Handles missing values
    - Converts feature dictionaries to model-ready arrays
    """
    
    def __init__(self):
        """Initialize the feature processor with a StandardScaler"""
        self.scaler = StandardScaler()  # For standardizing numerical features
        self.is_fitted = False  # Track if scaler has been fitted
    
    def fit(self, data):
        """
        Fit the scaler on training data
        Args:
            data: Pandas DataFrame containing training features
        """
        self.scaler.fit(data)  # Learn mean and std from training data
        self.is_fitted = True  # Mark scaler as fitted
    
    def transform(self, features_dict):
        """
        Transform a dictionary of features into scaled numpy array
        Args:
            features_dict: Dictionary of feature names to values
        Returns:
            Numpy array of scaled features ready for model prediction
        """
        # Convert dictionary to DataFrame with one row
        features_df = pd.DataFrame([features_dict])
        
        # Convert to numpy array
        features_array = features_df.values
        
        # Scale features if scaler has been fitted
        if self.is_fitted:
            features_array = self.scaler.transform(features_array)
        
        return features_array
    
    def preprocess(self, df):
        """
        Preprocess a DataFrame of features by:
        1. Handling missing values
        2. Standardizing numerical features
        Args:
            df: Pandas DataFrame containing features to preprocess
        Returns:
            Preprocessed DataFrame
        """
        # Fill missing values with -1 (acts as missing value indicator)
        df = df.fillna(-1)  
        
        # Identify numerical columns
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        
        # Standardize numerical features
        if len(numerical_cols) > 0:
            if not self.is_fitted:
                # Fit and transform if first time seeing data
                self.fit(df[numerical_cols])
                df[numerical_cols] = self.scaler.transform(df[numerical_cols])
            else:
                # Only transform if already fitted
                df[numerical_cols] = self.scaler.transform(df[numerical_cols])
        
        return df
