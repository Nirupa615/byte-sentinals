import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import json
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

class AIThreatAnalyzer:
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
        if pd.notna(row['Image']):
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
            if pd.notna(row[col]):
                for pattern in self.threat_patterns['suspicious_paths']:
                    if re.search(pattern, row[col], re.IGNORECASE):
                        threats.append(f"Suspicious path pattern: {pattern}")
        
        # Analyze network ports
        if pd.notna(row['DestinationPort']):
            port = int(row['DestinationPort']) if str(row['DestinationPort']).isdigit() else 0
            for threat_info in self.threat_patterns['network_threats']:
                if port == threat_info['port']:
                    threats.append(threat_info['threat'])
        
        # Analyze file extensions
        if pd.notna(row['TargetFilename']):
            for pattern in self.threat_patterns['file_threats']:
                if re.search(pattern, row['TargetFilename'], re.IGNORECASE):
                    threats.append(f"Suspicious file type: {pattern}")
        
        return threats
    
    def generate_threat_context(self, row):
        """Generate AI-powered threat context using pattern matching"""
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

class GenAIExplanationGenerator:
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
        """Generate natural language explanation for anomalies"""
        process_name = row['Image'].split('\\')[-1] if pd.notna(row['Image']) else 'Unknown Process'
        
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
        if pd.notna(row['UtcTime']):
            explanation += f"\n🕐 **Timestamp**: {row['UtcTime']}"
        
        # Add confidence score
        explanation += f"\n🎯 **AI Confidence**: {threat_context['confidence']*100:.1f}%"
        
        return explanation

class AISecurityAssistant:
    def __init__(self, df):
        self.df = df
        self.ai_analyzer = AIThreatAnalyzer()
        self.explanation_gen = GenAIExplanationGenerator()
    
    def query_security_data(self, query):
        """Process natural language queries about security data"""
        query_lower = query.lower()
        
        if 'total anomalies' in query_lower or 'how many anomalies' in query_lower:
            count = self.df['anomaly_flag'].sum()
            return f"📊 **Total Anomalies Detected**: {count} out of {len(self.df)} events"
        
        elif 'high risk' in query_lower:
            high_risk = self.df[self.df['risk_score'] >= 70]
            return f"🔴 **High Risk Events**: {len(high_risk)} events detected"
        
        elif 'powershell' in query_lower:
            powershell_events = self.df[self.df['Image'].str.contains('powershell.exe', case=False, na=False)]
            return f"💻 **PowerShell Events**: {len(powershell_events)} events found"
        
        elif 'network' in query_lower:
            network_events = self.df[self.df['DestinationPort'].notna()]
            return f"🌐 **Network Activity**: {len(network_events)} network connections detected"
        
        elif 'top processes' in query_lower:
            top_procs = self.df['Image'].value_counts().head(5)
            result = "🔍 **Top 5 Processes**:\n"
            for proc, count in top_procs.items():
                result += f"• {proc.split('/')[-1]}: {count} events\n"
            return result
        
        else:
            return "🤖 **AI Assistant**: I can help you analyze anomalies, threat patterns, and security events. Try asking about 'total anomalies', 'high risk events', 'powershell activity', or 'network connections'."
    
    def get_threat_summary(self):
        """Generate AI-powered threat summary"""
        summary = {
            'total_events': len(self.df),
            'anomalies': self.df['anomaly_flag'].sum(),
            'high_risk': len(self.df[self.df['risk_score'] >= 70]),
            'medium_risk': len(self.df[(self.df['risk_score'] >= 40) & (self.df['risk_score'] < 70)]),
            'low_risk': len(self.df[self.df['risk_score'] < 40]),
            'most_active_threats': []
        }
        
        # Find most common threat patterns
        all_threats = []
        for idx, row in self.df.iterrows():
            if row['anomaly_flag'] == 1:
                threats = self.ai_analyzer.analyze_threat_patterns(row)
                all_threats.extend(threats)
        
        from collections import Counter
        threat_counts = Counter(all_threats)
        summary['most_active_threats'] = threat_counts.most_common(5)
        
        return summary

print("=== Enhanced Sysmon Phase-1 with AI Features ===")

# Load CSV
df = pd.read_csv("sysmon.csv")
print("Total logs loaded:", len(df))

# Feature engineering
df["Hour"] = pd.to_datetime(df["UtcTime"], errors="coerce").dt.hour

features = df[
    ["EventID", "Image", "ParentImage", "DestinationPort", "TargetFilename", "Hour"]
].copy()

# Handle missing values
text_cols = ["Image", "ParentImage", "TargetFilename"]
num_cols = ["EventID", "DestinationPort", "Hour"]

for col in text_cols:
    features[col] = features[col].fillna("NONE")

for col in num_cols:
    features[col] = features[col].fillna(0)

# Encode categorical columns
encoder = LabelEncoder()
for col in text_cols:
    features[col] = encoder.fit_transform(features[col])

# Train Isolation Forest
model = IsolationForest(
    n_estimators=50,
    contamination=0.03,
    random_state=42
)

model.fit(features)

# Predict anomalies
df["anomaly_flag"] = model.predict(features)
df["anomaly_flag"] = df["anomaly_flag"].map({1: 0, -1: 1})

# ML-BASED RISK SCORE
anomaly_scores = model.decision_function(features)

# Convert anomaly score → risk score (0–100)
df["risk_score"] = np.interp(
    anomaly_scores,
    (anomaly_scores.min(), anomaly_scores.max()),
    (100, 0)
).astype(int)

# Severity mapping
def severity(score):
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

df["severity"] = df["risk_score"].apply(severity)

# === AI ENHANCEMENTS ===
print("\n🤖 Initializing AI Analysis Engine...")

# Initialize AI components
ai_analyzer = AIThreatAnalyzer()
explanation_gen = GenAIExplanationGenerator()
security_assistant = AISecurityAssistant(df)

# Generate AI threat context for anomalies
print("🧠 Analyzing threat patterns with AI...")
df['ai_threat_context'] = df.apply(lambda row: ai_analyzer.generate_threat_context(row), axis=1)

# Generate AI explanations for anomalies
print("📝 Generating natural language explanations...")
df['ai_explanation'] = df.apply(
    lambda row: explanation_gen.generate_explanation(
        row, row['ai_threat_context'], row['risk_score']
    ) if row['anomaly_flag'] == 1 else "No anomalies detected",
    axis=1
)

# Generate AI threat summary
threat_summary = security_assistant.get_threat_summary()

print("\n🎯 AI Analysis Complete!")
print(f"📊 Total Events: {threat_summary['total_events']}")
print(f"🚨 Anomalies: {threat_summary['anomalies']}")
print(f"🔴 High Risk: {threat_summary['high_risk']}")
print(f"🟡 Medium Risk: {threat_summary['medium_risk']}")
print(f"🟢 Low Risk: {threat_summary['low_risk']}")

if threat_summary['most_active_threats']:
    print("\n🔥 Top Threat Patterns:")
    for threat, count in threat_summary['most_active_threats']:
        print(f"  • {threat}: {count} occurrences")

# Save enhanced output
df.to_csv("sysmon_ai_predictions.csv", index=False)

# Save AI analysis results separately
ai_results = {
    'threat_summary': threat_summary,
    'sample_explanations': df[df['anomaly_flag'] == 1][['UtcTime', 'Image', 'risk_score', 'ai_explanation']].head(5).to_dict('records')
}

with open("ai_analysis_results.json", "w") as f:
    json.dump(ai_results, f, indent=2, default=str)

print(f"\n✅ Enhanced output saved as sysmon_ai_predictions.csv")
print(f"✅ AI analysis saved as ai_analysis_results.json")

# Demo AI Assistant
print("\n🤖 AI Security Assistant Demo:")
print(security_assistant.query_security_data("total anomalies"))
print(security_assistant.query_security_data("high risk events"))
print(security_assistant.query_security_data("top processes"))
