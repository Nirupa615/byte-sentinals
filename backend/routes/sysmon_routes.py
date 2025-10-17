import os
import json
import tempfile
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from datetime import datetime

# Create blueprint
sysmon_bp = Blueprint('sysmon', __name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'json', 'xml', 'evtx'}

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@sysmon_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle file upload for Sysmon logs
    Accepts JSON, XML, or EVTX files
    """
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file part in the request'
        }), 400
    
    file = request.files['file']
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No selected file'
        }), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        
        try:
            # Create a temporary file
            temp_dir = os.path.join(current_app.root_path, 'static_uploads', 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            
            # Save the file temporarily
            temp_path = os.path.join(temp_dir, f"upload_{int(datetime.utcnow().timestamp())}_{filename}")
            file.save(temp_path)
            
            # Process the file based on its type
            if file_ext == 'json':
                events = process_json_file(temp_path)
            elif file_ext == 'xml':
                events = process_xml_file(temp_path)
            elif file_ext == 'evtx':
                events = process_evtx_file(temp_path)
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Unsupported file format'
                }), 400
            
            # Clean up the temporary file
            try:
                os.remove(temp_path)
            except Exception as e:
                current_app.logger.warning(f"Could not remove temporary file {temp_path}: {str(e)}")
            
            return jsonify({
                'status': 'success',
                'filename': filename,
                'events_processed': len(events),
                'events': events[:100]  # Return first 100 events to avoid huge responses
            })
            
        except Exception as e:
            current_app.logger.error(f"Error processing file {filename}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Error processing file: {str(e)}'
            }), 500
    
    return jsonify({
        'status': 'error',
        'message': 'File type not allowed. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS)
    }), 400

def process_json_file(filepath):
    """Process JSON format Sysmon logs"""
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'events' in data:
                return data['events']
            return [data]  # Single event
        except json.JSONDecodeError as e:
            current_app.logger.error(f"Invalid JSON file: {str(e)}")
            raise ValueError("Invalid JSON format")

def process_xml_file(filepath):
    """Process XML format Sysmon logs"""
    # TODO: Implement XML parsing for Sysmon logs
    # This is a placeholder implementation
    current_app.logger.warning("XML processing not yet implemented")
    return []

def process_evtx_file(filepath):
    """Process Windows EVTX format Sysmon logs"""
    # TODO: Implement EVTX parsing
    # This requires additional libraries like python-evtx
    current_app.logger.warning("EVTX processing not yet implemented")
    return []

@sysmon_bp.route('/parse', methods=['POST'])
def parse_events():
    """
    Parse and validate Sysmon events from JSON payload
    Expected format: { "events": [...] }
    """
    try:
        data = request.get_json()
        if not data or 'events' not in data:
            return jsonify({
                'status': 'error',
                'message': 'No events provided in the request'
            }), 400
        
        events = data['events']
        if not isinstance(events, list):
            return jsonify({
                'status': 'error',
                'message': 'Events should be an array'
            }), 400
        
        # Validate each event
        validated_events = []
        for i, event in enumerate(events):
            try:
                # Basic validation
                if not isinstance(event, dict):
                    current_app.logger.warning(f"Event at index {i} is not an object")
                    continue
                
                # Ensure required fields
                if 'event_id' not in event:
                    event['event_id'] = f"evt_{i}"
                if 'timestamp' not in event:
                    event['timestamp'] = datetime.utcnow().isoformat()
                
                validated_events.append(event)
                
            except Exception as e:
                current_app.logger.error(f"Error validating event at index {i}: {str(e)}")
                continue
        
        return jsonify({
            'status': 'success',
            'total_events': len(events),
            'valid_events': len(validated_events),
            'events': validated_events[:100]  # Return first 100 events
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in parse_events: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error parsing events: {str(e)}'
        }), 500
