import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import numpy as np

print("=== Sysmon Phase-1 Script Started ===")

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

# --- 🔥 ML-BASED RISK SCORE ---
# Lower score = more anomalous
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

# Save output
df.to_csv("sysmon_predictions.csv", index=False)

print("Total anomalies detected:", df["anomaly_flag"].sum())
print("Output saved as sysmon_predictions.csv")

