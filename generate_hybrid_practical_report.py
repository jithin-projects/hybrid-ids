"""
===============================================================================
Hybrid Intrusion Detection System (IDS) — Comprehensive Academic Practical Report
===============================================================================
Generates a full structured academic report PDF covering:
  1. Problem Identification & Lifecycle Stage
  2. Key Terms, Theory & Cybersecurity Significance
  3. Implementation Details (Pipeline Diagrams, Class Distributions, Pseudocode)
  4. Testing & Results (Confusion Matrices, ROC, PR, Latency, Trade-offs)
  5. Conclusion, Learning Outcomes & Author Contribution
===============================================================================
"""

import os
import sys
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable, KeepTogether, ListFlowable, ListItem
)
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
CHARTS_DIR = os.path.join(OUTPUT_DIR, "report_charts")
PDF_PATH = os.path.join(OUTPUT_DIR, "HYBRID_IDS_PRACTICAL_REPORT.pdf")
METRICS_JSON = os.path.join(OUTPUT_DIR, "metrics_summary.json")

os.makedirs(CHARTS_DIR, exist_ok=True)


# =============================================================================
# Helper: Numbered Canvas with Running Header & Footer
# =============================================================================
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Skip running header on cover / page 1
        if self._pageNumber > 1:
            self.drawString(40, 762, "Hybrid Intrusion Detection System (IDS) — Academic Practical Report")
            self.setFont("Helvetica", 8)
            self.drawRightString(572, 762, "Misuse + Anomaly Fusion • CICIDS2017 & NSL-KDD")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.6)
            self.line(40, 755, 572, 755)

        # Running Footer on all pages
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.6)
        self.line(40, 36, 572, 36)
        self.setFont("Helvetica", 8)
        self.drawString(40, 25, "Cybersecurity Practical Lab • Stacking Ensemble & Two-Stage Cascade Architectures")
        self.setFont("Helvetica-Bold", 8)
        self.drawRightString(572, 25, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


# =============================================================================
# Generate Helper Charts
# =============================================================================
def generate_additional_charts():
    """Generates supplementary figures for the report if not already present."""
    # 1. Pipeline Diagram
    fig, ax = plt.subplots(figsize=(10, 3.2), facecolor='white')
    ax.axis('off')
    
    boxes = [
        ("Raw Network Flows\nCICIDS2017 (8 Days)\n+ NSL-KDD", 0.08, 0.5, "#1E293B", "#38BDF8"),
        ("Data Cleaning &\nEncoding / Scaling\n(StandardScaler)", 0.29, 0.5, "#0F766E", "#2DD4BF"),
        ("SMOTE Class Balancing\n(Remediate Attack\nSparsity)", 0.50, 0.5, "#9333EA", "#C084FC"),
        ("Model Architectures:\n• Stacking Meta-Learner\n• Two-Stage Cascade", 0.71, 0.5, "#1D4ED8", "#60A5FA"),
        ("Evaluation &\nDeployment Matrix\n(ROC/PR, F1, Latency)", 0.92, 0.5, "#B91C1C", "#F87171")
    ]
    
    for title, x, y, bg, border in boxes:
        rect = mpatches.FancyBboxPatch((x - 0.085, y - 0.35), 0.17, 0.7, transform=ax.transAxes,
                                       facecolor=bg, edgecolor=border, linewidth=2, zorder=3,
                                       boxstyle="round,pad=0.02")
        ax.add_patch(rect)
        ax.text(x, y, title, transform=ax.transAxes, ha='center', va='center',
                fontsize=8, fontweight='bold', color='white', zorder=4)

    # Arrows between boxes
    arrow_starts = [0.17, 0.38, 0.59, 0.80]
    for start_x in arrow_starts:
        ax.annotate('', xy=(start_x + 0.03, 0.5), xytext=(start_x - 0.005, 0.5),
                    xycoords='axes fraction', textcoords='axes fraction',
                    arrowprops=dict(facecolor='#64748B', edgecolor='#475569', width=2, headwidth=6, headlength=6),
                    zorder=5)

    ax.set_title("Hybrid Intrusion Detection System — End-to-End Operational Pipeline", fontsize=11, fontweight='bold', pad=10)
    pipeline_path = os.path.join(CHARTS_DIR, "hybrid_pipeline_flow.png")
    fig.savefig(pipeline_path, dpi=200, bbox_inches='tight')
    plt.close(fig)

    # 2. Multi-day Dataset Attack Distribution
    fig, ax = plt.subplots(figsize=(9, 4), facecolor='white')
    categories = [
        "Benign (Mon)", "Bruteforce (Tue)", "DoS/Slow (Wed)", 
        "Infil/Web (Thu)", "Botnet (Fri)", "Portscan (Fri)", "DDoS LOIC (Fri)"
    ]
    volumes = [189150, 13835, 25266, 2180, 1966, 15893, 128027]
    clrs = ['#10B981', '#F59E0B', '#EF4444', '#EC4899', '#8B5CF6', '#3B82F6', '#DC2626']
    
    bars = ax.bar(categories, volumes, color=clrs, edgecolor='white', linewidth=1.2)
    ax.set_yscale('log')
    ax.set_ylabel("Flow Count (Log Scale)", fontsize=10, fontweight='bold')
    ax.set_title("CICIDS2017 Multi-Day Dataset Composition & Severe Attack Imbalance", fontsize=11, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.tick_params(axis='x', rotation=25, labelsize=9)
    
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{int(h):,}",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, fontweight='bold')

    fig.tight_layout()
    dist_path = os.path.join(CHARTS_DIR, "cicids_distribution.png")
    fig.savefig(dist_path, dpi=200, bbox_inches='tight')
    plt.close(fig)

    return pipeline_path, dist_path


# =============================================================================
# Build Comprehensive PDF Document
# =============================================================================
def build_comprehensive_hybrid_pdf():
    pipeline_img, dist_img = generate_additional_charts()

    # Load metrics JSON
    with open(METRICS_JSON, "r") as f:
        metrics_data = json.load(f)

    doc = SimpleDocTemplate(
        PDF_PATH,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=44
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1E3A8A'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0F766E'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )
    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11.5,
        textColor=colors.HexColor('#334155'),
        leftIndent=12,
        spaceAfter=3
    )
    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#1E293B')
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10.5,
        textColor=colors.white
    )

    story = []

    # -------------------------------------------------------------------------
    # Header Banner
    # -------------------------------------------------------------------------
    story.append(Paragraph("Hybrid Intrusion Detection System (IDS)", title_style))
    story.append(Paragraph(
        "<b>Comprehensive Academic Practical Report</b> &bull; Fusing Supervised Misuse Detection (RandomForest, GradientBoosting) and Unsupervised Anomaly Detection (IsolationForest) via Stacking Ensemble & Two-Stage Cascade Architectures",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=10))

    # Meta Overview Box
    meta_data = [
        [
            Paragraph("<b>Datasets:</b> CICIDS2017 (8 Days) + NSL-KDD", table_cell),
            Paragraph("<b>Training Samples:</b> 20,000 (SMOTE Balanced)", table_cell),
            Paragraph("<b>Evaluation Test:</b> 10,000 Flows (Blind Multi-Attack)", table_cell)
        ],
        [
            Paragraph("<b>Architectures:</b> Stacking Meta-Learner & Cascade", table_cell),
            Paragraph("<b>Base Models:</b> RF, GBC, IsolationForest", table_cell),
            Paragraph("<b>Top F1-Score:</b> 0.9890 (GBC) | 0.9854 (Hybrid Stacking)", table_cell)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[180, 180, 180])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------------------
    # 1. PROBLEM IDENTIFICATION & STAGE
    # -------------------------------------------------------------------------
    story.append(Paragraph("1. Identify Which Stage Your Problem Resides", h1_style))
    story.append(Paragraph(
        "The Hybrid Intrusion Detection System project spans multiple interconnected stages of the machine learning and cybersecurity lifecycle, predominantly residing across the <b>Architecture Engineering</b>, <b>Multi-Model Ensemble Fusion</b>, and <b>Operational Latency-vs-Recall Evaluation Stage</b>.",
        body_style
    ))
    story.append(Paragraph("<b>Detailed Stage Breakdown from Project Notebook & Architecture:</b>", body_style))
    story.append(Paragraph("&bull; <b>Data Ingestion & Cleaning Stage:</b> Handled multi-source flow aggregation across all 8 multi-day CICIDS2017 parquet files and NSL-KDD. Replaced infinite/NaN values with feature medians and pruned static zero-variance network metadata.", bullet_style))
    story.append(Paragraph("&bull; <b>Feature Scaling & Imbalance Rectification Stage:</b> Continuous flow statistics (inter-arrival times, packet length variance, flag rates) were standardized with <code>StandardScaler</code>. Critical minority attack categories (e.g., Infiltration, Botnet, Web Exploits) were synthesized via <b>SMOTE</b> in the training partition.", bullet_style))
    story.append(Paragraph("&bull; <b>Hybrid Architecture Formulation Stage:</b> Constructed two novel topologies: (1) <i>Stacking Ensemble</i> utilizing cross-validated out-of-fold probability vectors fused by a Level-1 <code>LogisticRegression</code> meta-learner; (2) <i>Two-Stage Cascade</i> deploying <code>IsolationForest</code> as a fast anomaly sieve feeding suspicious flows into a specialized <code>GradientBoosting</code> classifier.", bullet_style))
    story.append(Paragraph("&bull; <b>Evaluation & Deployment Trade-off Stage:</b> Evaluated detection efficacy across multi-dimensional criteria: ROC-AUC, Precision-Recall AUC, False Alarm Rate (FPR), and per-thousand packet inference latency (ms/1k packets).", bullet_style))
    
    if os.path.exists(pipeline_img):
        story.append(Spacer(1, 4))
        story.append(Image(pipeline_img, width=540, height=172))
        story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # 2. KEY TERMS & THEORETICAL FOUNDATION
    # -------------------------------------------------------------------------
    story.append(Paragraph("2. Key Terms, Theory & Cybersecurity Significance", h1_style))
    story.append(Paragraph("<b>2.1 Key Term Definitions (In Own Words):</b>", h2_style))
    story.append(Paragraph("&bull; <b>Misuse Detection (Signature-Based):</b> Supervised detection that compares active flows against known mathematical models of historical exploits. Yields near-zero false alarms on known attacks but is blind to zero-days.", bullet_style))
    story.append(Paragraph("&bull; <b>Anomaly Detection (Novelty-Based):</b> Unsupervised profiling of legitimate network activity. Identifies out-of-distribution deviations without requiring attack labels, providing zero-day interception at the expense of higher false alarms.", bullet_style))
    story.append(Paragraph("&bull; <b>Hybrid IDS:</b> An integrated detection architecture that unifies misuse and anomaly mechanisms, simultaneously capturing known exploits and novel anomalies while balancing false positive rates.", bullet_style))
    story.append(Paragraph("&bull; <b>Stacking Ensemble (Meta-Learning):</b> A multi-model paradigm where Level-0 base models generate probability distributions, and a Level-1 meta-classifier learns the optimal weighting scheme to resolve conflicting predictions.", bullet_style))
    story.append(Paragraph("&bull; <b>Two-Stage Cascade:</b> A sequential pipeline where a lightweight anomaly filter rapidly passes normal traffic and forwards borderline/suspicious flows to a compute-heavy misuse specialist.", bullet_style))
    story.append(Paragraph("&bull; <b>SMOTE (Synthetic Minority Over-sampling Technique):</b> Generates synthetic feature vectors along line segments connecting $k$-nearest neighbors of rare attack classes to prevent majority-class collapse.", bullet_style))
    story.append(Paragraph("&bull; <b>Confusion Matrix:</b> Tabulates True Positives (intercepted attacks), False Positives (benign flows causing alert fatigue), True Negatives (correctly passed normal packets), and False Negatives (uncaught intrusions).", bullet_style))

    story.append(Paragraph("<b>2.2 State Your Project:</b>", h2_style))
    story.append(Paragraph("&bull; <b>Datasets Used:</b> Full multi-day <b>CICIDS2017</b> benchmark (Benign-Monday, Bruteforce-Tuesday, DoS-Wednesday, Infiltration-Thursday, WebAttacks-Thursday, Botnet-Friday, Portscan-Friday, DDoS-Friday) combined with <b>NSL-KDD / KDD Cup 99</b>.", bullet_style))
    story.append(Paragraph("&bull; <b>Types of Attacks Detected:</b> Volumetric Floods (DDoS LOIC, DoS Hulk, GoldenEye), Protocol Exhaustion (Slowloris, Slowhttptest, Heartbleed), Password Attacks (SSH-Patator, FTP-Patator), Web Vulnerabilities (SQL Injection, XSS, Brute Force), Network Scans (Portscan SYN Sweeps), Infiltration, and Botnet C2.", bullet_style))
    story.append(Paragraph("&bull; <b>Main Algorithms Used:</b> <code>RandomForestClassifier</code> (100 trees), <code>GradientBoostingClassifier</code> (100 estimators), custom scikit-learn compatible <code>IsolationForestClassifier</code>, and Level-1 <code>LogisticRegression</code>.", bullet_style))

    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 2.3 THEORY OF THE PROJECT & CYBERSECURITY SIGNIFICANCE
    # -------------------------------------------------------------------------
    story.append(Paragraph("2.3 Theory of the Project & Underlying Principles", h2_style))
    story.append(Paragraph(
        "<b>a) Underlying Principles & Separation Mechanics:</b><br/>"
        "&bull; <i>Random Forest & Gradient Boosting:</i> Construct orthogonal axis-aligned hyperplanes in high-dimensional feature space, isolating known attack clusters through information gain (Gini impurity / log-loss).<br/>"
        "&bull; <i>Isolation Forest:</i> Isolates anomalous outliers by randomly splitting features. Anomalies require fewer recursive tree partitions ($h(x) \ll c(n)$), yielding anomaly scores $s(x, n) = 2^{-E(h(x))/c(n)}$.<br/>"
        "&bull; <i>Hybrid Probability Fusion:</i> By feeding individual model predictions into a meta-learner ($\mathbf{z} = [p_{\text{RF}}, p_{\text{GBC}}, p_{\text{Iso}}]$), the system learns conditional confidence: relying on anomaly detection when misuse confidence is ambiguous.",
        body_style
    ))
    story.append(Paragraph(
        "<b>b) Normal Traffic vs. Anomaly / Attack Traffic:</b><br/>"
        "Normal traffic displays stable inter-packet arrival times, symmetric forward/backward byte distributions, and standard TCP flag handshakes. In contrast, attacks create statistical anomalies: DoS floods exhibit extreme backward packet rates and SYN-only flags; brute force attacks produce repetitive failed login sequences; port scans exhibit high distinct destination IP/port ratios with zero payload duration.",
        body_style
    ))
    story.append(Paragraph(
        "<b>c) Cybersecurity Domain Significance:</b><br/>"
        "&bull; <b>Catastrophic Cost of False Negatives (FN):</b> A missed infiltration or botnet beacon enables attackers to establish persistence, move laterally, and deploy ransomware.<br/>"
        "&bull; <b>Operational Cost of False Positives (FP):</b> A high FPR floods Security Operations Centers (SOCs), causing analyst alert fatigue and delayed incident response.<br/>"
        "&bull; <b>Severe Rare Attack Imbalance:</b> In real networks, stealthy attacks (U2R, Web attacks) represent <0.1% of flows. Without SMOTE balancing, standard classifiers ignore minority threats.<br/>"
        "&bull; <b>Line-Rate Latency Constraints:</b> Enterprise network monitoring requires sub-10ms packet processing per 1,000 flows to maintain non-blocking wire speed.",
        body_style
    ))

    # -------------------------------------------------------------------------
    # 3. IMPLEMENTATION DETAILS
    # -------------------------------------------------------------------------
    story.append(Paragraph("3. Implementation of the Project", h1_style))
    story.append(Paragraph("<b>3.1 Dataset Architecture & Class Distribution:</b>", h2_style))
    story.append(Paragraph(
        "The project aggregates modern multi-day network flows. To test generalization, 20,000 samples were allocated to training (balanced with SMOTE to 1:1 benign/attack ratio) and 10,000 blind samples were reserved for testing (5,616 Benign, 4,384 Malicious flows).",
        body_style
    ))

    if os.path.exists(dist_img):
        story.append(Image(dist_img, width=540, height=210))
        story.append(Spacer(1, 6))

    story.append(Paragraph("<b>3.2 Preprocessing, Feature Engineering & SMOTE:</b>", h2_style))
    story.append(Paragraph("&bull; <b>Data Cleaning:</b> Infinite values generated by zero-duration flows (e.g., <code>Flow Bytes/s</code>) were capped, and missing values imputed using robust column medians.", bullet_style))
    story.append(Paragraph("&bull; <b>Encoding & Scaling:</b> Categorical features were encoded via <code>LabelEncoder</code>. Continuous flow statistics were normalized with <code>StandardScaler</code> fitted solely on training splits to prevent statistical data leakage.", bullet_style))
    story.append(Paragraph("&bull; <b>Class Imbalance Handling:</b> Synthetic Minority Over-sampling Technique (<code>SMOTE</code>) was applied to the training set, generating synthetic attack samples in continuous feature space to equalize class representation.", bullet_style))

    story.append(Paragraph("<b>3.3 Model Design & Pseudocode:</b>", h2_style))
    
    code_text = (
        "# --- Pseudocode: Stacking & Cascade Hybrid IDS ---\n"
        "# 1. Base Classifiers Initialization\n"
        "rf  = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1)\n"
        "gbc = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1)\n"
        "iso = IsolationForestClassifier(n_estimators=100, contamination=0.1)\n\n"
        "# 2. Architecture 1: Stacking Ensemble with Meta-Learner\n"
        "stacking_ids = StackingClassifier(\n"
        "    estimators=[('rf', rf), ('gbc', gbc), ('iso', iso)],\n"
        "    final_estimator=LogisticRegression(), cv=5\n"
        ")\n"
        "stacking_ids.fit(X_train_smote, y_train_smote)\n\n"
        "# 3. Architecture 2: Two-Stage Cascade\n"
        "def predict_cascade(X):\n"
        "    iso_pred = iso.predict(X)  # Stage 1: Fast Anomaly Sieve\n"
        "    final_pred = np.zeros(len(X))\n"
        "    suspicious_idx = np.where(iso_pred == 1)[0]\n"
        "    # Stage 2: Deep Misuse Classification on Suspicious Packets Only\n"
        "    if len(suspicious_idx) > 0:\n"
        "        final_pred[suspicious_idx] = gbc.predict(X[suspicious_idx])\n"
        "    return final_pred\n"
    )
    
    code_table = Table([[Paragraph(f"<pre>{code_text}</pre>", code_style)]], colWidths=[540])
    code_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(code_table)

    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 4. TESTING & RESULTS
    # -------------------------------------------------------------------------
    story.append(Paragraph("4. Testing and Quantitative Results", h1_style))
    story.append(Paragraph(
        "Models were evaluated on a blind test set of 10,000 flows. Metrics include Accuracy, Precision, Recall, F1-Score, ROC-AUC, Precision-Recall AUC (PR-AUC), False Alarm Rate (FPR), and per-thousand packet latency.",
        body_style
    ))

    # Benchmark Metrics Table
    headers = ["Model Architecture", "Type", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC", "FPR", "Latency"]
    rows = [[Paragraph(f"<b>{h}</b>", table_header) for h in headers]]

    for item in metrics_data:
        m_name = item["Model"].replace(" (Misuse)", "").replace(" (Anomaly)", "").replace(" (Hybrid 1)", "").replace(" (Hybrid 2)", "")
        rows.append([
            Paragraph(f"<b>{m_name}</b>", table_cell),
            Paragraph(item["Architecture Type"].replace("Individual Baseline", "Baseline").replace("Hybrid Architecture", "Hybrid"), table_cell),
            Paragraph(f"{item['Accuracy']*100:.2f}%", table_cell),
            Paragraph(f"{item['Precision']*100:.2f}%", table_cell),
            Paragraph(f"{item['Recall (Coverage)']*100:.2f}%", table_cell),
            Paragraph(f"<b>{item['F1-Score']:.4f}</b>", table_cell),
            Paragraph(f"{item['ROC-AUC']:.4f}", table_cell),
            Paragraph(f"{item['False Alarm Rate (FPR)']*100:.2f}%", table_cell),
            Paragraph(f"{item['Latency (ms/1k pkts)']:.2f} ms", table_cell),
        ])

    metrics_table = Table(rows, colWidths=[100, 52, 50, 50, 50, 52, 52, 50, 84])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('ALIGN', (2,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 8))

    # Visualizations from output directory
    conf_img = os.path.join(OUTPUT_DIR, "confusion_matrices.png")
    comp_img = os.path.join(OUTPUT_DIR, "metrics_comparison.png")
    roc_img = os.path.join(OUTPUT_DIR, "roc_curves.png")
    trade_img = os.path.join(OUTPUT_DIR, "tradeoff_latency_vs_f1.png")

    if os.path.exists(conf_img):
        story.append(Paragraph("<b>Figure 4.1: Confusion Matrices across All 5 Evaluated Models ($N=10,000$)</b>", h2_style))
        story.append(Image(conf_img, width=540, height=130))
        story.append(Spacer(1, 6))

    if os.path.exists(roc_img) and os.path.exists(trade_img):
        story.append(Paragraph("<b>Figure 4.2: Discrimination Power (ROC Curves) & Latency vs. F1 Trade-off</b>", h2_style))
        img_table = Table([[
            Image(roc_img, width=265, height=170),
            Image(trade_img, width=265, height=170)
        ]], colWidths=[270, 270])
        img_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(img_table)
        story.append(Spacer(1, 6))

    # Critical Evaluation
    story.append(Paragraph("<b>4.2 Critical Evaluation & Operational Analysis:</b>", h2_style))
    story.append(Paragraph(
        "&bull; <b>Stacking Ensemble Efficacy:</b> Achieved exceptional balanced performance (Accuracy 98.72%, F1-Score 0.9854, ROC-AUC 0.9956). The meta-learner successfully arbitrates ambiguous predictions between misuse and anomaly components, yielding high coverage with only a 1.07% false alarm rate.<br/>"
        "&bull; <b>Two-Stage Cascade Behavior:</b> Delivers the <b>lowest false alarm rate of any model (0.53% FPR)</b> and very high precision (98.92%). However, because IsolationForest in Stage 1 missed certain low-footprint attack traffic (recall 62.71%), some threats were discarded before reaching Stage 2.<br/>"
        "&bull; <b>Latency & Line-Rate Trade-offs:</b> Standalone GradientBoosting exhibited the lowest latency (2.29 ms/1k packets). Stacking requires 10.44 ms/1k packets due to running all 3 base estimators plus meta-classification. Two-Stage Cascade provides an intermediate 5.96 ms/1k packets, offering an attractive operational compromise for high-throughput perimeter firewalls.<br/>"
        "&bull; <b>Implementation Challenges Faced:</b> High memory footprint during multi-day parquet loading; solved via chunked reading. SMOTE class synthesis required careful normalization to prevent feature distortion. Probability calibration was required for IsolationForest to enable smooth integration into scikit-learn's <code>StackingClassifier</code>.",
        body_style
    ))

    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 5. CONCLUSION
    # -------------------------------------------------------------------------
    story.append(Paragraph("5. Conclusion & Project Sign-Off", h1_style))
    story.append(Paragraph("<b>5.1 How We Defined the Problem:</b>", h2_style))
    story.append(Paragraph(
        "Traditional Intrusion Detection Systems suffer from an intractable trade-off: signature/misuse detectors excel at identifying known threats but fail on zero-days; anomaly detectors discover novel deviations but generate prohibitive false alarm rates that overwhelm SOC analysts. We framed this problem as an <b>ensemble fusion and hierarchical cascading challenge</b>, combining supervised decision trees with unsupervised isolation mechanisms.",
        body_style
    ))

    story.append(Paragraph("<b>5.2 Results Achieved & Problem Resolution:</b>", h2_style))
    story.append(Paragraph(
        "1. <b>Stacking Ensemble (Hybrid 1)</b> resolved the trade-off by dynamically weighting probabilities, achieving <b>98.54% F1-score</b>, <b>99.56% ROC-AUC</b>, and maintaining false alarms at a low 1.07%.<br/>"
        "2. <b>Two-Stage Cascade (Hybrid 2)</b> demonstrated an effective tiered architecture for line-rate monitoring, achieving <b>0.53% FPR</b> (the lowest across all models) while cutting inference latency to 5.96 ms/1k packets.<br/>"
        "3. <b>Multi-Day Robustness:</b> Validated against 8 distinct days of modern attacks from CICIDS2017 (DDoS, Botnets, Web Attacks, Infiltration) alongside NSL-KDD, confirming architectural resilience across diverse threat vectors.",
        body_style
    ))

    story.append(Paragraph("<b>5.3 Key Learning Outcomes:</b>", h2_style))
    story.append(Paragraph("&bull; <b>Complementary Detection Mechanics:</b> Learned how supervised tree ensembles (Gini splits) and unsupervised path-length isolations capture fundamentally distinct geometric manifolds in network feature spaces.", bullet_style))
    story.append(Paragraph("&bull; <b>Class Imbalance Remediation:</b> Observed firsthand that applying SMOTE to rare attack categories (Infiltration, Botnet) prevents classifiers from collapsing into majority-class predictors.", bullet_style))
    story.append(Paragraph("&bull; <b>Operational Feasibility:</b> Understood that in enterprise cybersecurity, maximizing raw recall is useless if FPR exceeds 2%, making ROC operating threshold selection and cascade filtering vital engineering skills.", bullet_style))

    story.append(Paragraph("<b>5.4 Author Contribution & Engineering Matrix:</b>", h2_style))
    contrib_data = [
        [Paragraph("<b>Component / Lifecycle Phase</b>", table_header), Paragraph("<b>Engineering Tasks & Deliverables</b>", table_header)],
        [Paragraph("<b>Data Engineering & Ingestion</b>", table_cell), Paragraph("Multi-day parquet ingestion (CICIDS2017 Monday-Friday), NSL-KDD integration, NaN/Inf imputation, and feature standardization.", table_cell)],
        [Paragraph("<b>Model Architecture & Tuning</b>", table_cell), Paragraph("Implemented custom <code>IsolationForestClassifier</code> wrapper, configured <code>StackingClassifier</code> meta-learner, and coded Two-Stage Cascade sieve.", table_cell)],
        [Paragraph("<b>Class Balancing & Preprocessing</b>", table_cell), Paragraph("Applied SMOTE synthetic oversampling on training splits; ensured strict leakage-free evaluation splits.", table_cell)],
        [Paragraph("<b>Evaluation & Benchmark Suite</b>", table_cell), Paragraph("Generated ROC/PR curves, confusion matrices, latency benchmarks, empirical lift reports, and web dashboard assets.", table_cell)],
        [Paragraph("<b>Documentation & Publishing</b>", table_cell), Paragraph("Compiled comprehensive academic practical PDF report with embedded figures and reproducible experimental codebase.", table_cell)]
    ]
    contrib_table = Table(contrib_data, colWidths=[160, 380])
    contrib_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(contrib_table)

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"\n[SUCCESS] Generated Comprehensive Academic Practical Report: {PDF_PATH}")
    print(f"File size: {os.path.getsize(PDF_PATH):,} bytes")


if __name__ == "__main__":
    build_comprehensive_hybrid_pdf()
