from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import pandas as pd
import json
import os
from ai_sysmon_analyzer import AIThreatAnalyzer, GenAIExplanationGenerator, AISecurityAssistant

app = Flask(__name__)
CORS(app)

# Global variables for analysis results
current_analysis = None
ai_assistant = None

@app.route('/')
def index():
    return send_from_directory('.', 'ai_dashboard.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

@app.route('/api/ai-analyze', methods=['POST'])
def ai_analyze():
    global current_analysis, ai_assistant
    
    try:
        # In a real implementation, you'd process uploaded file data
        # For now, we'll use the existing CSV file
        df = pd.read_csv("sysmon.csv")
        
        # Run the enhanced AI analysis
        exec(open("ai_sysmon_analyzer.py").read())
        
        # Load the results
        results_df = pd.read_csv("sysmon_ai_predictions.csv")
        
        with open("ai_analysis_results.json", "r") as f:
            ai_results = json.load(f)
        
        # Initialize AI assistant with the data
        ai_assistant = AISecurityAssistant(results_df)
        
        # Prepare response data
        response_data = {
            'totalEvents': len(results_df),
            'anomaliesDetected': int(results_df['anomaly_flag'].sum()),
            'highRiskEvents': len(results_df[results_df['risk_score'] >= 70]),
            'mediumRiskEvents': len(results_df[(results_df['risk_score'] >= 40) & (results_df['risk_score'] < 70)]),
            'lowRiskEvents': len(results_df[results_df['risk_score'] < 40]),
            'aiConfidence': 87,  # This would be calculated based on model performance
            'threatPatterns': [item[0] for item in ai_results['threat_summary']['most_active_threats']],
            'explanations': []
        }
        
        # Add AI explanations for anomalies
        anomalies_df = results_df[results_df['anomaly_flag'] == 1].head(10)
        for idx, row in anomalies_df.iterrows():
            explanation = {
                'time': pd.to_datetime(row['UtcTime']).strftime('%H:%M') if pd.notna(row['UtcTime']) else 'Unknown',
                'process': row['Image'].split('\\')[-1] if pd.notna(row['Image']) else 'Unknown',
                'risk': int(row['risk_score']),
                'explanation': row.get('ai_explanation', 'AI analysis not available'),
                'threats': ['high' if row['risk_score'] >= 70 else 'medium' if row['risk_score'] >= 40 else 'low']
            }
            response_data['explanations'].append(explanation)
        
        current_analysis = response_data
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    global ai_assistant
    
    try:
        data = request.json
        query = data.get('query', '')
        
        if not ai_assistant:
            return jsonify({'response': 'Please run AI analysis first.'})
        
        response = ai_assistant.query_security_data(query)
        return jsonify({'response': response})
        
    except Exception as e:
        return jsonify({'response': f'Error processing query: {str(e)}'}), 500

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy', 'message': 'AI Sysmon Analyzer is running'})

if __name__ == '__main__':
    print("🤖 Starting AI-Powered Sysmon Analysis Server...")
    print("📊 Open http://localhost:5000 in your browser")
    print("🚀 AI features enabled: Threat Intelligence, Natural Language Processing, Security Assistant")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
