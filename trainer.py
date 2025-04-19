import pandas as pd
import math
import re
from urllib.parse import urlparse
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import RFE
from sklearn.metrics import precision_score, recall_score, f1_score

import numpy as np

# --- Load phishing URLs from local PhishTank CSV file ---
print("Loading phishing URLs from local file 'phishtank.csv'...")
try:
    df_phish = pd.read_csv("SimpleExtension/datasets/verified_online.csv")
    print(len(df_phish))
    phishing_urls = df_phish['url'].dropna().sample(n=10000, random_state=42).tolist()
except Exception as e:
    print("Failed to load phishing URLs from local file:", e)
    phishing_urls = []

# --- Load benign URLs from Tranco top sites ---
print("Downloading top domains from Tranco...")
try:
    tranco_raw = pd.read_csv('SimpleExtension/datasets/top-1m.csv', header=None, names=['rank', 'domain'])
    benign_urls = ['https://' + d for d in tranco_raw['domain'].sample(n=10000, random_state=42)]
except Exception as e:
    print("Failed to download Tranco list:", e)
    benign_urls = []

# Label data
urls = phishing_urls + benign_urls
labels = [1]*len(phishing_urls) + [0]*len(benign_urls)

print(f"Downloaded {len(phishing_urls)} phishing URLs and {len(benign_urls)} benign URLs")

# Feature extraction
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    full_url = url.lower()
    specials = ['%', '-', '=', '&', ';']
    keywords = ['login', 'verify', 'secure', 'account', 'signin']

    def entropy(domain):
        counts = {char: domain.count(char) for char in set(domain)}
        length = len(domain)
        return -sum((f / length) * math.log2(f / length) for f in counts.values())
    
    raw_entropy = entropy(hostname)
    entropy_binary = 1 if raw_entropy > 3.9 else 0  # Binary conversion

    return {
        'url_length': len(full_url),
        'dot_count': hostname.count('.'),
        'has_at': '@' in full_url,
        'special_char_count': sum(full_url.count(ch) for ch in specials),
        'entropy': raw_entropy,
        'suspicious_keywords': sum(kw in full_url for kw in keywords),
        'subdomain_length': sum(len(part) for part in hostname.split('.')[:-2]) if hostname.count('.') >= 2 else 0,
        'is_ip': bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))
    }

# Build dataframe
features = [extract_features(url) for url in urls]
df = pd.DataFrame(features)
df['label'] = labels

X = df.drop("label", axis=1)
y = df["label"]

# Normalize features - use RobustScaler to handle outliers
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)

# RFE for feature selection - Recursive Feature Elimination
print("\nPerforming Recursive Feature Elimination (RFE)...")
model = LogisticRegression()
rfe = RFE(model, n_features_to_select=5)
fit = rfe.fit(X_scaled, y)
print("RFE-selected:", X.columns[fit.support_])

# choose the best features
X_selected = X_scaled[:, fit.support_]

# Cross-validation with multiple k values
print("\nEvaluating model with k-fold cross-validation:")
k_options = [3, 5, 7, 10, 15]
best_k = None
best_score = 0

for k in k_options:
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    model = LogisticRegression()
    scores = cross_val_score(model, X_selected, y, cv=skf, scoring='accuracy')
    mean_score = scores.mean()
    print(f"k={k} | Mean Accuracy: {mean_score:.4f}")
    if mean_score > best_score:
        best_score = mean_score
        best_k = k

print(f"\nBest k found: {best_k} with accuracy: {best_score:.4f}")


# Final training on the selected features
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2, random_state=42)

final_model = LogisticRegression()
final_model.fit(X_train, y_train)
y_pred = final_model.predict(X_test)

# Classification report
y_probs = final_model.predict_proba(X_test)[:, 1]  # סיכוי לפישינג


# Export model weights
print("\nJavaScript-ready weights:")
print("const weights = {")
for name, coef in zip(X.columns, final_model.coef_[0]):
    print(f"  {name}: {coef:.4f},")
print("};")
print(f"const bias = {final_model.intercept_[0]:.4f};")

# Evaluate model performance
print("\nEvaluating model performance...")
precision = precision_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
tpr = tp / (tp + fn)
fpr = fp / (fp + tn)


print(f"Precision: {precision:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"True Positive Rate (TPR / Recall): {tpr:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")