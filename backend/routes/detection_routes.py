from flask import Blueprint, request, jsonify, current_app
import os
import joblib
import numpy as np
from datetime import datetime

# Create blueprint
detection_bp = Blueprint('detection', __name__)

# Initialize model (will be loaded when needed)
model = None

def load_model():
    """Load the pre-trained ML model"""
    global model
    if model is None:
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'backend', 'ml_model', 'model.pkl'
        )
        try:
            model = joblib.load(model_path)
            current_app.logger.info("ML model loaded successfully")
        except Exception as e:
            current_app.logger.error(f"Error loading model: {str(e)}")
            model = None
    return model

@detection_bp.route('/analyze', methods=['POST'])
def analyze_logs():
    """
    Analyze sysmon logs for potential threats
    Expected JSON format:
    {
        "events": [
            {
                "event_id": 1,
                "process_name": "cmd.exe",
                "command_line": "whoami",
                "user": "SYSTEM",
                "timestamp": "2023-01-01T12:00:00Z"
                # ... other event fields
            }
        ]
    }
    """
    try:
        data = request.get_json()
        if not data or 'events' not in data:
            return jsonify({
                'status': 'error',
                'message': 'No events provided'
            }), 400

        # Load model if not already loaded
        model = load_model()
        if model is None:
            return jsonify({
                'status': 'error',
                'message': 'Model not available'
            }), 500

        # Process each event
        results = []
        for event in data['events']:
            try:
                # TODO: Add proper feature extraction
                features = extract_features(event)
                
                # Make prediction
                prediction = model.predict_proba([features])[0]
                threat_score = float(prediction[1])  # Assuming binary classification
                
                results.append({
                    'event_id': event.get('event_id'),
                    'threat_score': threat_score,
                    'is_malicious': threat_score > 0.7,  # Threshold
                    'details': {
                        'process': event.get('process_name', 'unknown'),
                        'command': event.get('command_line', ''),
                        'user': event.get('user', 'unknown')
                    }
                })
            except Exception as e:
                current_app.logger.error(f"Error processing event: {str(e)}")
                continue

        return jsonify({
            'status': 'success',
            'analysis_time': datetime.utcnow().isoformat(),
            'total_events': len(data['events']),
            'processed_events': len(results),
            'threats_found': sum(1 for r in results if r['is_malicious']),
            'results': results
        })

    except Exception as e:
        current_app.logger.error(f"Error in analyze_logs: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def extract_features(event):
    """Extract features from a single event for model prediction"""
    # TODO: Implement proper feature extraction based on your model's requirements
    # This is a placeholder implementation
    features = [
        len(event.get('command_line', '')),  # Example feature: command line length
        1 if 'powershell' in event.get('process_name', '').lower() else 0,  # PowerShell usage
        len(event.get('user', '')),  # Username length
        # Add more features as needed
    ]
    return features

# Add more routes as needed
@detection_bp.route('/stats', methods=['GET'])
def get_detection_stats():
    """Get statistics about detections"""
    # TODO: Implement actual statistics collection
    return jsonify({
        'status': 'success',
        'total_analyzed': 0,  # Placeholder
        'threats_detected': 0,  # Placeholder
        'last_analyzed': None  # Placeholder
    })
