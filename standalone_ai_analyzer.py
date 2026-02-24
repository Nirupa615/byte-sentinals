import csv
import json
import re
from collections import Counter
from datetime import datetime
import math
import random

class SimpleAIThreatAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            'suspicious_process': [
                r'powershell\.exe.*-enc', r'cmd\.exe.*\/c', r'wscript\.exe',
                r'cscript\.exe', r'rundll32\.exe', r'regsvr32\.exe'
            ],
            'suspicious_paths': [
                r'\\AppData\\Local\\Temp\\', r'\\Users\\Public\\', r'\\Windows\\Tasks\\',
                r'\\System32\\drivers\\etc\\', r'\\Windows\\Temp\\'
            ],
            'network_threats': [
                {'port': 4444, 'threat': 'Possible backdoor'},
                {'port': 1337, 'threat': 'Common malware port'},
                {'port': 9999, 'threat': 'Suspicious high port'},
                {'port': 8080, 'threat': 'Alternative HTTP port'}
            ],
            'file_threats': [
                r'\.exe$', r'\.scr$', r'\.bat$', r'\.cmd$', r'\.ps1$', r'\.vbs$'
            ]
        }
        
        self.process_reputation = {
            'high_risk': ['svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe'],
            'medium_risk': ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'],
            'low_risk': ['notepad.exe', 'calc.exe', 'chrome.exe', 'explorer.exe']
        }
    
    def analyze_threat_patterns(self, row):
        threats = []
        
        # Analyze process name
        if row.get('Image'):
            process_name = row['Image'].split('\\')[-1].lower()
            for pattern in self.threat_patterns['suspicious_process']:
                if re.search(pattern, process_name, re.IGNORECASE):
                    threats.append(f"Suspicious process pattern: {pattern}")
            
            # Check process reputation
            for risk_level, processes in self.process_reputation.items():
                if process_name in processes:
                    threats.append(f"Process reputation: {risk_level}")
        
        # Analyze file paths
        for col in ['Image', 'TargetFilename']:
            if row.get(col):
                for pattern in self.threat_patterns['suspicious_paths']:
                    if re.search(pattern, row[col], re.IGNORECASE):
                        threats.append(f"Suspicious path pattern: {pattern}")
        
        # Analyze network ports
        if row.get('DestinationPort'):
            try:
                port = int(row['DestinationPort'])
                for threat_info in self.threat_patterns['network_threats']:
                    if port == threat_info['port']:
                        threats.append(threat_info['threat'])
            except:
                pass
        
        # Analyze file extensions
        if row.get('TargetFilename'):
            for pattern in self.threat_patterns['file_threats']:
                if re.search(pattern, row['TargetFilename'], re.IGNORECASE):
                    threats.append(f"Suspicious file type: {pattern}")
        
        return threats
    
    def generate_threat_context(self, row):
        context = {
            'threat_level': 'Low',
            'confidence': 0.1,
            'indicators': [],
            'mitre_attacks': []
        }
        
        threats = self.analyze_threat_patterns(row)
        context['indicators'] = threats
        
        # Calculate threat level
        if len(threats) >= 3:
            context['threat_level'] = 'Critical'
            context['confidence'] = 0.9
        elif len(threats) >= 2:
            context['threat_level'] = 'High'
            context['confidence'] = 0.7
        elif len(threats) >= 1:
            context['threat_level'] = 'Medium'
            context['confidence'] = 0.5
        
        # Map to MITRE ATT&CK techniques
        if any('powershell' in t.lower() for t in threats):
            context['mitre_attacks'].append('T1059.001 - PowerShell')
        if any('cmd' in t.lower() for t in threats):
            context['mitre_attacks'].append('T1059.003 - Command Shell')
        if any('temp' in t.lower() for t in threats):
            context['mitre_attacks'].append('T1083 - File and Directory Discovery')
        
        return context

class SimpleAIExplanationGenerator:
    def __init__(self):
        self.explanation_templates = {
            'high_risk': [
                "🚨 **CRITICAL THREAT DETECTED**: {process} is exhibiting highly suspicious behavior.",
                "The activity involves {indicators} which are commonly associated with malware campaigns.",
                "Immediate investigation recommended. This pattern matches known attack techniques: {mitre}."
            ],
            'medium_risk': [
                "⚠️ **SUSPICIOUS ACTIVITY**: {process} behavior requires attention.",
                "Detected {indicators} that could indicate potential security concerns.",
                "Monitor this activity closely. Related MITRE techniques: {mitre}."
            ],
            'low_risk': [
                "ℹ️ **ANOMALOUS BEHAVIOR**: {process} shows unusual but not necessarily malicious activity.",
                "Minor indicators detected: {indicators}.",
                "Consider reviewing this activity for context."
            ]
        }
    
    def generate_explanation(self, row, threat_context, risk_score):
        process_name = row['Image'].split('\\')[-1] if row.get('Image') else 'Unknown Process'
        
        # Select template based on risk score
        if risk_score >= 70:
            templates = self.explanation_templates['high_risk']
        elif risk_score >= 40:
            templates = self.explanation_templates['medium_risk']
        else:
            templates = self.explanation_templates['low_risk']
        
        # Format explanation
        indicators = ', '.join(threat_context['indicators'][:3]) if threat_context['indicators'] else 'unusual patterns'
        mitre = ', '.join(threat_context['mitre_attacks'][:2]) if threat_context['mitre_attacks'] else 'N/A'
        
        explanation = "\n".join(templates).format(
            process=process_name,
            indicators=indicators,
            mitre=mitre
        )
        
        # Add time-based context
        if row.get('UtcTime'):
            explanation += f"\n🕐 **Timestamp**: {row['UtcTime']}"
        
        # Add confidence score
        explanation += f"\n🎯 **AI Confidence**: {threat_context['confidence']*100:.1f}%"
        
        return explanation

class SimpleIsolationForest:
    """Simple anomaly detection without sklearn"""
    def __init__(self, contamination=0.03, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.threshold = None
    
    def fit(self, features):
        # Simple scoring based on feature variance
        self.feature_stats = {}
        for col in features.columns:
            values = features[col]
            self.feature_stats[col] = {
                'mean': sum(values) / len(values),
                'std': math.sqrt(sum((x - sum(values)/len(values))**2 for x in values) / len(values))
            }
        
        # Calculate anomaly scores
        scores = []
        for row in features.data:
            score = 0
            for col in features.columns:
                val = row[col]
                mean = self.feature_stats[col]['mean']
                std = self.feature_stats[col]['std']
                if std > 0:
                    score += abs(val - mean) / std
            scores.append(score)
        
        # Set threshold based on contamination
        scores.sort()
        threshold_idx = int(len(scores) * (1 - self.contamination))
        self.threshold = scores[threshold_idx] if threshold_idx < len(scores) else scores[-1]
    
    def predict(self, features):
        predictions = []
        for row in features.data:
            score = 0
            for col in features.columns:
                val = row[col]
                mean = self.feature_stats[col]['mean']
                std = self.feature_stats[col]['std']
                if std > 0:
                    score += abs(val - mean) / std
            
            predictions.append(-1 if score > self.threshold else 1)
        return predictions
    
    def decision_function(self, features):
        scores = []
        for row in features.data:
            score = 0
            for col in features.columns:
                val = row[col]
                mean = self.feature_stats[col]['mean']
                std = self.feature_stats[col]['std']
                if std > 0:
                    score += abs(val - mean) / std
            scores.append(-score)  # Negative for consistency with sklearn
        return scores

def load_csv(filename):
    """Simple CSV loader without pandas"""
    data = []
    with open(filename, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            data.append(row)
    return data

def save_csv(data, filename, fieldnames):
    """Simple CSV saver without pandas"""
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def simple_label_encoder(values):
    """Simple label encoder without sklearn"""
    unique_vals = list(set(values))
    encoding_map = {val: i for i, val in enumerate(unique_vals)}
    return [encoding_map[val] for val in values]

print("=== AI-Powered Sysmon Phase-1 (Standalone) ===")

# Load CSV
data = load_csv("sysmon.csv")
print(f"Total logs loaded: {len(data)}")

# Convert to feature format
features = []
for row in data:
    # Extract hour from timestamp
    hour = 0
    if row.get('UtcTime'):
        try:
            # Simple hour extraction
            if ':' in row['UtcTime']:
                time_part = row['UtcTime'].split()[-1]
                hour = int(time_part.split(':')[0]) if time_part else 0
        except:
            hour = 0
    
    features.append({
        'EventID': int(row.get('EventID', 0)),
        'Image': row.get('Image', 'NONE'),
        'ParentImage': row.get('ParentImage', 'NONE'),
        'DestinationPort': int(row.get('DestinationPort', 0)) if row.get('DestinationPort') else 0,
        'TargetFilename': row.get('TargetFilename', 'NONE'),
        'Hour': hour
    })

# Encode categorical features
image_vals = [f['Image'] for f in features]
parent_vals = [f['ParentImage'] for f in features]
target_vals = [f['TargetFilename'] for f in features]

image_encoded = simple_label_encoder(image_vals)
parent_encoded = simple_label_encoder(parent_vals)
target_encoded = simple_label_encoder(target_vals)

# Create feature matrix
feature_matrix = []
for i, f in enumerate(features):
    feature_matrix.append([
        f['EventID'],
        image_encoded[i],
        parent_encoded[i],
        f['DestinationPort'],
        target_encoded[i],
        f['Hour']
    ])

# Simple DataFrame-like structure
class SimpleDataFrame:
    def __init__(self, data):
        self.data = data
        self.columns = list(data[0].keys()) if data else []
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, key):
        if isinstance(key, str):
            return [row.get(key) for row in self.data]
        return self.data[key]
    
    def iterrows(self):
        for i, row in enumerate(self.data):
            yield i, row

# Create DataFrame
df = SimpleDataFrame(data)

# Train simple anomaly detection
print("🤖 Training AI anomaly detection model...")
model = SimpleIsolationForest(contamination=0.03)

# Convert features for model
feature_df = SimpleDataFrame([
    {'EventID': f[0], 'Image': f[1], 'ParentImage': f[2], 
     'DestinationPort': f[3], 'TargetFilename': f[4], 'Hour': f[5]}
    for f in feature_matrix
])

model.fit(feature_df)

# Predict anomalies
predictions = model.predict(feature_df)
anomaly_scores = model.decision_function(feature_df)

# Add predictions to data
for i, row in enumerate(data):
    row['anomaly_flag'] = 1 if predictions[i] == -1 else 0
    
    # Calculate risk score (0-100)
    score = anomaly_scores[i]
    min_score = min(anomaly_scores)
    max_score = max(anomaly_scores)
    if max_score != min_score:
        risk_score = int(((score - min_score) / (max_score - min_score)) * 100)
    else:
        risk_score = 50
    row['risk_score'] = 100 - risk_score  # Invert so higher = more risky
    
    # Add severity
    if row['risk_score'] >= 70:
        row['severity'] = 'High'
    elif row['risk_score'] >= 40:
        row['severity'] = 'Medium'
    else:
        row['severity'] = 'Low'

# Initialize AI components
print("🧠 Initializing AI analysis engine...")
ai_analyzer = SimpleAIThreatAnalyzer()
explanation_gen = SimpleAIExplanationGenerator()

# Generate AI threat context and explanations
print("📝 Generating AI-powered explanations...")
for row in data:
    threat_context = ai_analyzer.generate_threat_context(row)
    row['ai_threat_context'] = json.dumps(threat_context)
    
    if row['anomaly_flag'] == 1:
        explanation = explanation_gen.generate_explanation(row, threat_context, row['risk_score'])
        row['ai_explanation'] = explanation
    else:
        row['ai_explanation'] = "No anomalies detected"

# Calculate summary statistics
total_events = len(data)
anomalies = sum(1 for row in data if row['anomaly_flag'] == 1)
high_risk = sum(1 for row in data if row['risk_score'] >= 70)
medium_risk = sum(1 for row in data if 40 <= row['risk_score'] < 70)
low_risk = sum(1 for row in data if row['risk_score'] < 40)

# Find most common threat patterns
all_threats = []
for row in data:
    if row['anomaly_flag'] == 1:
        threats = ai_analyzer.analyze_threat_patterns(row)
        all_threats.extend(threats)

threat_counts = Counter(all_threats)
most_common_threats = threat_counts.most_common(5)

print("\n🎯 AI Analysis Complete!")
print(f"📊 Total Events: {total_events}")
print(f"🚨 Anomalies: {anomalies}")
print(f"🔴 High Risk: {high_risk}")
print(f"🟡 Medium Risk: {medium_risk}")
print(f"🟢 Low Risk: {low_risk}")

if most_common_threats:
    print("\n🔥 Top Threat Patterns:")
    for threat, count in most_common_threats:
        print(f"  • {threat}: {count} occurrences")

# Save results
fieldnames = list(data[0].keys()) if data else []
save_csv(data, "sysmon_ai_predictions.csv", fieldnames)

# Save AI analysis summary
ai_results = {
    'threat_summary': {
        'total_events': total_events,
        'anomalies': anomalies,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'most_active_threats': most_common_threats
    },
    'sample_explanations': [
        {
            'UtcTime': row['UtcTime'],
            'Image': row['Image'],
            'risk_score': row['risk_score'],
            'ai_explanation': row['ai_explanation']
        }
        for row in data if row['anomaly_flag'] == 1
    ][:5]
}

with open("ai_analysis_results.json", "w") as f:
    json.dump(ai_results, f, indent=2)

print(f"\n✅ Enhanced output saved as sysmon_ai_predictions.csv")
print(f"✅ AI analysis saved as ai_analysis_results.json")
print("🚀 AI features are now ready! Open ai_dashboard.html in your browser.")
