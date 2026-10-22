# Hybrid Intrusion Detection System (IDS)

A Hybrid Intrusion Detection System combining **Misuse Detection** (supervised machine learning for known attack patterns) and **Anomaly Detection** (unsupervised novelty/outlier detection for zero-day/unknown deviations) across two state-of-the-art architectures:

1. **Stacking Ensemble Architecture** (Multi-Model Probability Fusion via Meta-Learner)
2. **Two-Stage Cascade Architecture** (Fast Anomaly Sieve + High-Precision Misuse Classifier)

---

## 🎯 Project Objectives & Theoretical Foundation

Traditional Intrusion Detection Systems suffer from a fundamental dichotomy:
- **Misuse/Signature Detectors (RandomForest, GradientBoosting)**: Excel at accurately classifying known attacks with minimal false alarms, but struggle with zero-day attacks or variations in attack signatures.
- **Anomaly Detectors (IsolationForest)**: Excel at detecting novel traffic deviations, but generate higher false positive rates (FPR) on benign variations.

### The Hybrid Solution
By unifying both paradigms into two complementary architectures:
- **Architecture 1 (Stacking Ensemble)**: Base-level detectors (`RandomForestClassifier`, `GradientBoostingClassifier`, and `IsolationForestClassifier`) generate out-of-fold probability vectors $\mathbf{P} = [p_{\text{RF}}, p_{\text{GBC}}, p_{\text{Iso}}]$, which a Level-1 meta-estimator (`LogisticRegression`) optimally weights to maximize detection coverage while suppressing false alarms.
- **Architecture 2 (Two-Stage Cascade)**: Stage 1 deploys `IsolationForest` as an ultra-fast anomalous packet filter that directly passes clear benign traffic. Suspect traffic is subsequently gated into Stage 2 (`GradientBoostingClassifier`) for deep signature classification.

---

## 📊 Datasets & Feature Engineering

1. **Primary Dataset**: **CICIDS2017 Multi-Day Benchmark (All 8 Day-Level Files)**:
   - `Benign-Monday-no-metadata.parquet`: Baseline normal network traffic (no attacks)
   - `Bruteforce-Tuesday-no-metadata.parquet`: FTP-Patator & SSH-Patator brute force
   - `DoS-Wednesday-no-metadata.parquet`: DoS Hulk, GoldenEye, Slowloris, Slowhttptest, Heartbleed
   - `Infiltration-Thursday-no-metadata.parquet`: Infiltration & privilege escalation
   - `WebAttacks-Thursday-no-metadata.parquet`: Web Brute Force, XSS, SQL Injection
   - `Botnet-Friday-no-metadata.parquet`: ARES Botnet traffic
   - `Portscan-Friday-no-metadata.parquet`: Fast & stealth port scanning (SYN sweep)
   - `DDoS-Friday-no-metadata.parquet`: Distributed Denial of Service (LOIC)
   - Captures realistic modern network flows with 78 behavioral network metrics (flow duration, inter-arrival time, packet length variance, flag counters).
2. **Supplement Benchmark Dataset**: **NSL-KDD / KDD Cup 99** (`fetch_kddcup99` / `KDDTrain+.txt`)
   - Provides extensive historical attack distributions (DoS, Probe, U2R, R2L).
3. **Class Imbalance Remediation**:
   - **SMOTE (Synthetic Minority Over-sampling Technique)** applied to training splits to ensure minority attack vectors are preserved without model degradation.
4. **Standardization**:
   - Zero-mean, unit-variance scaling (`StandardScaler`) with feature alignment across disparate feature spaces.

---

## 🛠️ Technology Stack & Tools Used

- **Supervised Misuse Detectors**: `sklearn.ensemble.RandomForestClassifier`, `sklearn.ensemble.GradientBoostingClassifier`
- **Unsupervised Anomaly Detector**: `sklearn.ensemble.IsolationForest` (wrapped via custom `IsolationForestClassifier`)
- **Meta-Learner**: `sklearn.linear_model.LogisticRegression`
- **Ensemble Meta-Framework**: `sklearn.ensemble.StackingClassifier`
- **Class Balancing**: `imblearn.over_sampling.SMOTE`
- **Metrics & Analysis**: `classification_report`, `roc_auc_score`, `precision_recall_curve`, `confusion_matrix`
- **Visualization**: `matplotlib`, `seaborn`

---

## 🚀 How to Run the Project

### Basic Execution (Default Balanced Benchmark)
```bash
python hybrid_ids.py
```

### Custom Sample Size or Output Directory
```bash
python hybrid_ids.py --samples 30000 --outdir output/
```

---

## 📈 Generated Artifacts in `output/`

| File | Description |
| :--- | :--- |
| `roc_curves.png` | Overlay of ROC Curves with AUC performance comparisons |
| `pr_curves.png` | Precision-Recall Curves showing detection purity vs coverage |
| `confusion_matrices.png` | Side-by-side Normal vs Attack confusion matrices for all models |
| `metrics_comparison.png` | Multi-bar comparison across Accuracy, Precision, Recall, F1, and AUC |
| `detection_lift.png` | Empirical % Lift in detection coverage and F1 over standalone baselines |
| `tradeoff_latency_vs_f1.png` | Throughput (inference ms/1k packets) vs Detection Efficacy tradeoff |
| `metrics_summary.csv` | Full tabular benchmark metrics |
| `DETECTION_LIFT_REPORT.md` | Comprehensive experimental report and architectural findings |
