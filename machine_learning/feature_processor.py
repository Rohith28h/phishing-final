import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

class FeatureProcessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, data):
        """Fit the scaler on training data"""
        self.scaler.fit(data)
        self.is_fitted = True
    
    def transform(self, features_dict):
        """Transform a dictionary of features into scaled array"""
        # Convert dictionary to DataFrame with one row
        features_df = pd.DataFrame([features_dict])
        
        # Convert to numpy array
        features_array = features_df.values
        
        # Scale if scaler is fitted
        if self.is_fitted:
            features_array = self.scaler.transform(features_array)
        
        return features_array
    
    def preprocess(self, df):
        """Preprocess a DataFrame of features"""
        # Handle missing values
        df = df.fillna(-1)  # Fill missing values with -1 (indicator for missing)
        
        # Normalize numerical features if needed
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        if len(numerical_cols) > 0 and not self.is_fitted:
            self.fit(df[numerical_cols])
            df[numerical_cols] = self.scaler.transform(df[numerical_cols])
        elif len(numerical_cols) > 0 and self.is_fitted:
            df[numerical_cols] = self.scaler.transform(df[numerical_cols])
        
        return df
