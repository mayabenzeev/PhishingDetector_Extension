# Phishing Detection Browser Extension

## Abstract
This project implements a lightweight, browser-based phishing detection solution as a Chrome extension. It integrates a Random Forest model to detect phishing attempts in real-time by analyzing webpage features derived from URL structure and dynamic runtime indicators. The extension performs client-side classification, providing immediate warnings about potentially malicious pages without server-side reliance, enabling fast and robust protection against sophisticated phishing threats.

## Introduction
Phishing websites pose a significant cyber threat by impersonating legitimate services to steal user data, leading to financial loss, identity theft, and data breaches. Our solution addresses the limitations of traditional defenses like blacklists and signature filters by implementing a machine learning-based approach that combines:

## Technical Implementation

### Detection Methods
The extension implements two primary detection methods:

1. **Static URL Analysis**
   - URL length analysis
   - Domain structure examination
   - Character entropy evaluation
   - IP presence detection
   - Free hosting detection

2. **Dynamic Behavior Analysis**
   - DOM changes monitoring
   - Script execution patterns
   - Page load time analysis
   - Event listener tracking

### Machine Learning Model
- **Algorithm**: Random Forest
- **Features**: 13 carefully selected features combining static and dynamic indicators
- **Performance Metrics**:
  - True Positive Rate (TPR): 97%
  - False Positive Rate (FPR): 6%
  - Threshold: 0.86

## Installation
1. Clone this repository
2. Open Chrome/Chromium browser
3. Navigate to `chrome://extensions/`
4. Enable "Developer mode"
5. Click "Load unpacked" and select the extension directory "SimpleExtension"

## Performance Evaluation

### Model Training
- Dataset composition: Phishing URLs from PhishTank and benign URLs from Tranco
- Class ratio: 1:4 (phishing:benign) for real-world representation
- Cross-validation: 5-fold with out-of-fold predictions

### Key Metrics
1. **Coverage Test (35%)**
   - Measures phishing detection rate
   - Achieves 97% TPR

2. **Error Test (35%)**
   - Focuses on precision
   - 6% FPR achieved

3. **Response Time (10%)**
   - Real-time classification
   - Minimal browsing impact

4. **Memory Usage (10%)**
   - Efficient client-side processing
   - Optimized feature extraction

## Limitations and Future Work

### Current Limitations
1. **Data Quality and Generalization**
   - Limited structural complexity in benign dataset
   - Room for improvement in feature diversity

2. **Detection vs. Usability Balance**
   - Trade-off between TPR and false positives
   - Potential for threshold optimization

3. **Dynamic Feature Constraints**
   - Browser API restrictions limit access to some metrics
   - Limited access to low-level runtime data

### Future Improvements
1. **Model Enhancement**
   - Explore model stacking with complementary classifiers
   - Integration of heuristic rules

2. **Privacy and Efficiency**
   - Further privacy analysis of runtime signals
   - Performance optimization for diverse environments

## Authors
Maya Ben-Zeev & Nadav Goldrat
