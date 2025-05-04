import pandas as pd
import math
import re
from urllib.parse import urlparse
# from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import RFE
from sklearn.metrics import precision_score, recall_score, f1_score
import time
import numpy as np

# --- Load phishing URLs from local PhishTank CSV file ---
print("Loading phishing URLs from local file 'phishtank.csv'...")
try:
    df_phish = pd.read_csv("../../datasets/phishing.csv")
    print(len(df_phish))
    phishing_urls = df_phish['url'].dropna().sample(n=10000, random_state=42).tolist()
except Exception as e:
    print("Failed to load phishing URLs from local file:", e)
    phishing_urls = []

# --- Load benign URLs from Tranco top sites ---
print("Downloading top domains from Tranco...")
try:
    tranco_raw = pd.read_csv('../../datasets/benign.csv', header=None, names=['rank', 'domain'])
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

    # Subdomain length
    parts = hostname.split('.')
    subdomain_length = sum(len(part) for part in parts[:-2]) if len(parts) >= 3 else 0
    
    # Free hosting provider check
    free_hosting_providers = [
        "000webhost", "freehostia", "neocities", "wordpress",
        "blogspot", "netlify", "weebly", "github", "weeblysite"
    ]
    domain = parts[-2].lower() if len(parts) >= 2 else ''
    is_free_hosting = int(domain in free_hosting_providers)

    # Hyphen presence in URL segments
    has_hyphen = int('-' in hostname)

    return {
        'url_length': len(full_url),
        'dot_count': hostname.count('.'),
        'has_at': '@' in full_url,
        'special_char_count': sum(full_url.count(ch) for ch in specials),
        'entropy': raw_entropy,
        'suspicious_keywords': sum(kw in full_url for kw in keywords),
        'subdomain_length': subdomain_length,
        'is_ip': bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)),
        'is_free_hosting': is_free_hosting,
        'has_hyphen': has_hyphen
    }

# Build dataframe
features = [extract_features(url) for url in urls]
df = pd.DataFrame(features)
df['label'] = labels
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

X = df.drop("label", axis=1)
y = df["label"]

# Filter features from original X and rescale
X_selected = X


# Cross-validation with multiple k values
print("\nEvaluating model with k-fold cross-validation:")
k_options = [3, 5, 7, 10, 15]
best_k = None
best_score = 0

for k in k_options:
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

    scores = cross_val_score(model, X_selected, y, cv=skf, scoring='accuracy')
    mean_score = scores.mean()
    print(f"k={k} | Mean Accuracy: {mean_score:.4f}")
    if mean_score > best_score:
        best_score = mean_score
        best_k = k

print(f"\nBest k found: {best_k} with accuracy: {best_score:.4f}")

kf = StratifiedKFold(n_splits=best_k, shuffle=True, random_state=42)

print(f"Started looking for thresholds - {time.strftime('%H:%M:%S', time.localtime())}")
all_val_probs = []
all_val_labels = []

# train k-fold and save predictions
for train_idx, val_idx in kf.split(X_selected, y):
    X_train, X_val = X_selected.iloc[train_idx], X_selected.iloc[val_idx]
    y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    probs = model.predict_proba(X_val)[:, 1]

    all_val_probs.extend(probs)
    all_val_labels.extend(y_val)

# calculate F1 for every threshold
thresholds = np.linspace(0.1, 0.9, 50)
f1_scores_per_threshold = []

all_val_probs = np.array(all_val_probs)
all_val_labels = np.array(all_val_labels)

for t in thresholds:
    preds = (all_val_probs >= t).astype(int)
    f1 = f1_score(all_val_labels, preds)
    f1_scores_per_threshold.append(f1)

best_threshold = thresholds[np.argmax(f1_scores_per_threshold)]
print(f"Best threshold for max F1: {best_threshold:.3f}")


# Final training on the selected features
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2, random_state=42)

final_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
final_model.fit(X_train, y_train)
y_pred = final_model.predict(X_test)

# Classification report
y_probs = final_model.predict_proba(X_test)[:, 1]  # סיכוי לפישינג


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