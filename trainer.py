import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve
)
import joblib

# 1. Load and prepare data
df = pd.read_csv("../datasets/features.csv")
df['label'] = df['label'].astype(int)             
print("Label distribution:\n", df['label'].value_counts(), "\n")

# drop non‐numeric columns
X = df.drop(["label","url"], axis=1)
y = df["label"]

# 2. Optimize number of trees via OOB error
tree_range = list(range(10, 301, 10))
oob_errors = []
for n in tree_range:
    rf = RandomForestClassifier(
        n_estimators=n, oob_score=True, n_jobs=-1, random_state=42
    )
    rf.fit(X, y)
    oob_errors.append(1 - rf.oob_score_)
best_n = tree_range[np.argmin(oob_errors)]
print(f"Chosen n_estimators = {best_n}\n")

# 3. Feature importance & selection
rf_sel = RandomForestClassifier(
    n_estimators=best_n, n_jobs=-1, random_state=42
)
rf_sel.fit(X, y)
importances   = rf_sel.feature_importances_
indices       = np.argsort(importances)[::-1]
feature_names = X.columns.tolist()

# pick top‐k by MAE
mae_scores = []
for k in range(1, len(feature_names)+1):
    sel = [feature_names[i] for i in indices[:k]]
    scores = -cross_val_score(
        RandomForestClassifier(n_estimators=100, random_state=42),
        X[sel], y,
        cv=5,
        scoring="neg_mean_absolute_error",
        n_jobs=-1
    )
    mae_scores.append(scores.mean())
best_k = np.argmin(mae_scores) + 1
selected_features = [feature_names[i] for i in indices[:best_k]]
print(f"Selected top {best_k} features\n")
X_sel = X[selected_features]

# 4. Gather OOB‐tuned RF’s validation probabilities for ROC thresholding
print("Gathering validation probabilities for threshold tuning…")
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
all_val_probs  = []
all_val_labels = []

for train_idx, val_idx in skf.split(X_sel, y):
    y_train = y.iloc[train_idx]
    # guard: skip any fold with only one class
    if y_train.nunique() < 2:
        all_val_probs.extend([0.0] * len(val_idx))
        all_val_labels.extend(y.iloc[val_idx])
        continue

    m = RandomForestClassifier(n_estimators=100, random_state=42)
    m.fit(X_sel.iloc[train_idx], y_train)
    probs = m.predict_proba(X_sel.iloc[val_idx])[:, 1]
    all_val_probs.extend(probs)
    all_val_labels.extend(y.iloc[val_idx])

all_val_probs  = np.array(all_val_probs)
all_val_labels = np.array(all_val_labels)

# 5. ROC curve & threshold via Youden’s J
fpr_arr, tpr_arr, thr_arr = roc_curve(all_val_labels, all_val_probs)
j_scores = tpr_arr - fpr_arr
best_threshold = thr_arr[np.argmax(j_scores)]
print(f"Optimal threshold = {best_threshold:.3f}\n")

# 6. Final train/test split & evaluation
X_train, X_test, y_train, y_test = train_test_split(
    X_sel, y, test_size=0.2, random_state=42
)
final_model = RandomForestClassifier(n_estimators=100, random_state=42)
final_model.fit(X_train, y_train)

y_probs_test = final_model.predict_proba(X_test)[:, 1]
y_pred_test  = (y_probs_test >= best_threshold).astype(int)

cm = confusion_matrix(y_test, y_pred_test)
precision = precision_score(y_test, y_pred_test)
recall    = recall_score(y_test, y_pred_test)
f1        = f1_score(y_test, y_pred_test)
tpr       = cm[1,1] / (cm[1,1] + cm[1,0])
fpr       = cm[0,1] / (cm[0,1] + cm[0,0])

print("Final performance:")
print("Confusion Matrix:\n", cm)
print(f"Precision: {precision:.4f}")
print(f"Recall (TPR): {tpr:.4f}")
print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"F1 Score: {f1:.4f}\n")

# 7. Save model + metadata
joblib.dump({
    "model": final_model,
    "features": selected_features,
    "threshold": best_threshold
}, "rf_model_with_selection.pkl")
