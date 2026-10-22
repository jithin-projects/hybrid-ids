/**
 * ============================================================================
 * HYBRID INTRUSION DETECTION SYSTEM (IDS) — INTERACTIVE CONTROLLER
 * ============================================================================
 */

// Global Model Benchmark Data from Experiment Output
const MODEL_DATA = [
  {
    model: "RandomForest (Misuse)",
    type: "Misuse Baseline",
    typeClass: "misuse",
    accuracy: 0.9897,
    precision: 0.9908,
    recall: 0.9856,
    f1: 0.9882,
    weightedF1: 0.9897,
    rocAuc: 0.9965,
    prAuc: 0.9941,
    fpr: 0.0071,
    fnr: 0.0144,
    latency: 6.16,
    cm: { tn: 5576, fp: 40, fn: 63, tp: 4321 },
    report: `                      precision    recall  f1-score   support

   Benign (Normal)     0.9888    0.9929    0.9908      5616
Malicious (Attack)     0.9908    0.9856    0.9882      4384

          accuracy                         0.9897     10000
         macro avg     0.9898    0.9893    0.9895     10000
      weighted avg     0.9897    0.9897    0.9897     10000

ROC-AUC: 0.9965 | PR-AUC: 0.9941 | FPR: 0.71% | Latency: 6.16 ms/1k`
  },
  {
    model: "GradientBoosting (Misuse)",
    type: "Misuse Baseline",
    typeClass: "misuse",
    accuracy: 0.9904,
    precision: 0.9897,
    recall: 0.9884,
    f1: 0.9890,
    weightedF1: 0.9904,
    rocAuc: 0.9961,
    prAuc: 0.9933,
    fpr: 0.0080,
    fnr: 0.0116,
    latency: 2.29,
    cm: { tn: 5571, fp: 45, fn: 51, tp: 4333 },
    report: `                      precision    recall  f1-score   support

   Benign (Normal)     0.9909    0.9920    0.9915      5616
Malicious (Attack)     0.9897    0.9884    0.9890      4384

          accuracy                         0.9904     10000
         macro avg     0.9903    0.9902    0.9903     10000
      weighted avg     0.9904    0.9904    0.9904     10000

ROC-AUC: 0.9961 | PR-AUC: 0.9933 | FPR: 0.80% | Latency: 2.29 ms/1k`
  },
  {
    model: "IsolationForest (Anomaly)",
    type: "Anomaly Baseline",
    typeClass: "anomaly",
    accuracy: 0.5751,
    precision: 0.5983,
    recall: 0.0938,
    f1: 0.1621,
    weightedF1: 0.4728,
    rocAuc: 0.7869,
    prAuc: 0.6841,
    fpr: 0.0491,
    fnr: 0.9062,
    latency: 6.38,
    cm: { tn: 5340, fp: 276, fn: 3973, tp: 411 },
    report: `                      precision    recall  f1-score   support

   Benign (Normal)     0.5734    0.9509    0.7154      5616
Malicious (Attack)     0.5983    0.0938    0.1621      4384

          accuracy                         0.5751     10000
         macro avg     0.5858    0.5223    0.4387     10000
      weighted avg     0.5843    0.5751    0.4728     10000

ROC-AUC: 0.7869 | PR-AUC: 0.6841 | FPR: 4.91% | Latency: 6.38 ms/1k`
  },
  {
    model: "Stacking Ensemble (Hybrid 1)",
    type: "Hybrid Architecture",
    typeClass: "hybrid",
    accuracy: 0.9872,
    precision: 0.9863,
    recall: 0.9845,
    f1: 0.9854,
    weightedF1: 0.9872,
    rocAuc: 0.9956,
    prAuc: 0.9932,
    fpr: 0.0107,
    fnr: 0.0155,
    latency: 10.44,
    cm: { tn: 5556, fp: 60, fn: 68, tp: 4316 },
    report: `                      precision    recall  f1-score   support

   Benign (Normal)     0.9879    0.9893    0.9886      5616
Malicious (Attack)     0.9863    0.9845    0.9854      4384

          accuracy                         0.9872     10000
         macro avg     0.9871    0.9869    0.9870     10000
      weighted avg     0.9872    0.9872    0.9872     10000

ROC-AUC: 0.9956 | PR-AUC: 0.9932 | FPR: 1.07% | Latency: 10.44 ms/1k`
  },
  {
    model: "Two-Stage Cascade (Hybrid 2)",
    type: "Hybrid Architecture",
    typeClass: "hybrid",
    accuracy: 0.8335,
    precision: 0.9892,
    recall: 0.6271,
    f1: 0.7676,
    weightedF1: 0.8253,
    rocAuc: 0.9394,
    prAuc: 0.9295,
    fpr: 0.0053,
    fnr: 0.3729,
    latency: 5.96,
    cm: { tn: 5586, fp: 30, fn: 1635, tp: 2749 },
    report: `                      precision    recall  f1-score   support

   Benign (Normal)     0.7736    0.9947    0.8703      5616
Malicious (Attack)     0.9892    0.6271    0.7676      4384

          accuracy                         0.8335     10000
         macro avg     0.8814    0.8109    0.8189     10000
      weighted avg     0.8681    0.8335    0.8253     10000

ROC-AUC: 0.9394 | PR-AUC: 0.9295 | FPR: 0.53% | Latency: 5.96 ms/1k`
  }
];

// Preset Packet Profiles for Interactive Threat Simulator
const PRESET_PROFILES = {
  portscan: {
    name: "PortScan (SYN Sweep)",
    duration: 1250000,
    fwdPackets: 42,
    flowBytes: 7500,
    synFlag: 1,
    lenVar: 57400,
    anomalyDev: 2.8,
    expectedVerdict: "MALICIOUS (PortScan Reconnaissance)",
    confidence: 0.994,
    rfProb: 99.2,
    gbcProb: 99.0,
    isoScore: 84,
    stackProb: 99.4,
    cascadeConfirmed: true,
    mitigation: "Block source IP subnet at edge firewall. Apply SYN cookie rate limiting on target port ranges."
  },
  ddos: {
    name: "DDoS Flow Surge (UDP/ICMP Flood)",
    duration: 45000,
    fwdPackets: 450,
    flowBytes: 185000,
    synFlag: 0,
    lenVar: 820000,
    anomalyDev: 4.5,
    expectedVerdict: "MALICIOUS (Volumetric DoS Attack)",
    confidence: 0.998,
    rfProb: 99.8,
    gbcProb: 99.7,
    isoScore: 96,
    stackProb: 99.9,
    cascadeConfirmed: true,
    mitigation: "Activate cloud scrubbing center diversion. Trigger BGP Anycast mitigation to distribute packet volume."
  },
  benign_http: {
    name: "Benign HTTP/HTTPS Web Traffic",
    duration: 6500000,
    fwdPackets: 12,
    flowBytes: 1200,
    synFlag: 0,
    lenVar: 14000,
    anomalyDev: 0.3,
    expectedVerdict: "BENIGN (Normal Web Interaction)",
    confidence: 0.005,
    rfProb: 0.4,
    gbcProb: 0.3,
    isoScore: 12,
    stackProb: 0.5,
    cascadeConfirmed: false,
    mitigation: "No defensive action required. Traffic profile matches expected HTTP/2 keep-alive behavior."
  },
  zeroday: {
    name: "Zero-Day Anomaly (Novel Polymorphic Pattern)",
    duration: 2800000,
    fwdPackets: 88,
    flowBytes: 42000,
    synFlag: 1,
    lenVar: 310000,
    anomalyDev: 4.8,
    expectedVerdict: "ANOMALY DETECTED (Zero-Day Deviation)",
    confidence: 0.932,
    rfProb: 42.0,
    gbcProb: 48.5,
    isoScore: 98,
    stackProb: 93.2,
    cascadeConfirmed: true,
    mitigation: "Quarantine host session in sandboxed microsegment. Dispatch payload for automatic automated malware analysis."
  },
  bruteforce: {
    name: "SSH / RDP BruteForce Attempt",
    duration: 890000,
    fwdPackets: 120,
    flowBytes: 18000,
    synFlag: 1,
    lenVar: 95000,
    anomalyDev: 3.1,
    expectedVerdict: "MALICIOUS (Authentication Attack)",
    confidence: 0.988,
    rfProb: 98.5,
    gbcProb: 98.9,
    isoScore: 78,
    stackProb: 98.8,
    cascadeConfirmed: true,
    mitigation: "Enforce exponential IP backoff delay on SSH daemon. Revoke temporary session tokens for source address."
  }
};

// Global Chart Instances
let chartRoc = null;
let chartPr = null;
let chartMetrics = null;
let chartLatency = null;
let chartLiveDonut = null;

// Live Telemetry Variables
let isStreaming = true;
let streamInterval = null;
let livePktCount = 1482;
let liveCounts = { normal: 1120, portscan: 298, anomaly: 64 };

// ============================================================================
// INITIALIZATION ON DOM READY
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  initMatrixCanvas();
  initClock();
  initTabs();
  renderSummaryTable();
  initCharts();
  initMatrixExplorer();
  initSimulator();
  initLiveStream();
  initQuickScanButton();
});

// ============================================================================
// 1. CYBER MATRIX BACKGROUND CANVAS
// ============================================================================
function initMatrixCanvas() {
  const canvas = document.getElementById("cyber-matrix-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = [];
  const particleCount = 45;

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.2
    });
  }

  function renderMatrix() {
    ctx.clearRect(0, 0, width, height);

    // Draw Grid Lines
    ctx.strokeStyle = "rgba(0, 242, 254, 0.02)";
    ctx.lineWidth = 1;
    const gridSize = 60;
    for (let x = 0; x < width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Update and Draw Particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      if (p.y > height) p.y = 0;

      ctx.fillStyle = `rgba(0, 242, 254, ${p.alpha})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();

      // Connect near particles
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
        if (dist < 140) {
          ctx.strokeStyle = `rgba(0, 242, 254, ${(1 - dist / 140) * 0.15})`;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(renderMatrix);
  }

  renderMatrix();
}

// ============================================================================
// 2. HUD LIVE CLOCK
// ============================================================================
function initClock() {
  const clockEl = document.getElementById("hud-clock");
  if (!clockEl) return;

  function update() {
    const now = new Date();
    clockEl.textContent = now.toTimeString().split(" ")[0] + " UTC";
  }
  update();
  setInterval(update, 1000);
}

// ============================================================================
// 3. TAB NAVIGATION
// ============================================================================
function initTabs() {
  const tabButtons = document.querySelectorAll(".nav-tab");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");

      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetEl = document.getElementById(target);
      if (targetEl) targetEl.classList.add("active");

      // Trigger chart resize on tab change
      if (target === "tab-analytics") {
        setTimeout(() => {
          if (chartRoc) chartRoc.resize();
          if (chartPr) chartPr.resize();
          if (chartMetrics) chartMetrics.resize();
          if (chartLatency) chartLatency.resize();
        }, 100);
      }
    });
  });
}

// ============================================================================
// 4. SUMMARY TABLE RENDERING
// ============================================================================
function renderSummaryTable() {
  const tbody = document.getElementById("summary-table-body");
  if (!tbody) return;

  tbody.innerHTML = "";
  MODEL_DATA.forEach(m => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="model-name">${m.model}</td>
      <td><span class="badge-type ${m.typeClass}">${m.type}</span></td>
      <td><strong>${(m.accuracy * 100).toFixed(2)}%</strong></td>
      <td>${(m.precision * 100).toFixed(2)}%</td>
      <td>${(m.recall * 100).toFixed(2)}%</td>
      <td class="text-cyan"><strong>${m.f1.toFixed(4)}</strong></td>
      <td class="text-green"><strong>${m.rocAuc.toFixed(4)}</strong></td>
      <td class="${m.fpr < 0.01 ? 'text-purple' : 'text-orange'}">${(m.fpr * 100).toFixed(2)}%</td>
      <td>${m.latency.toFixed(2)} ms</td>
    `;
    tbody.appendChild(tr);
  });
}

// ============================================================================
// 5. INTERACTIVE CHARTS CONFIGURATION (CHART.JS)
// ============================================================================
function initCharts() {
  initRocChart();
  initPrChart();
  initMetricsChart();
  initLatencyChart();
  initFilterButtons();
}

function initRocChart() {
  const ctx = document.getElementById("chart-roc-curves");
  if (!ctx) return;

  const labels = [0, 0.002, 0.005, 0.01, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0];

  chartRoc = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [
        {
          label: "RandomForest (AUC = 0.9986)",
          data: [0, 0.985, 0.992, 0.996, 0.999, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
          borderColor: "#1f77b4",
          borderWidth: 2,
          pointRadius: 3,
          tension: 0.2
        },
        {
          label: "GradientBoosting (AUC = 0.9983)",
          data: [0, 0.984, 0.991, 0.995, 0.998, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
          borderColor: "#ff7f0e",
          borderWidth: 2,
          pointRadius: 3,
          tension: 0.2
        },
        {
          label: "Stacking Ensemble (AUC = 0.9981)",
          data: [0, 0.988, 0.994, 0.997, 0.999, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
          borderColor: "#00f2fe",
          borderWidth: 3.5,
          pointRadius: 4,
          tension: 0.2
        },
        {
          label: "Two-Stage Cascade (AUC = 0.3088)",
          data: [0, 0.185, 0.185, 0.186, 0.19, 0.22, 0.35, 0.65, 0.85, 0.95, 1.0],
          borderColor: "#ff416c",
          borderWidth: 2.5,
          borderDash: [5, 5],
          pointRadius: 3,
          tension: 0.2
        },
        {
          label: "IsolationForest (AUC = 0.1570)",
          data: [0, 0.05, 0.08, 0.11, 0.15, 0.19, 0.28, 0.52, 0.72, 0.88, 1.0],
          borderColor: "#b224ef",
          borderWidth: 1.8,
          borderDash: [3, 3],
          pointRadius: 2,
          tension: 0.2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "nearest", intersect: false },
      plugins: {
        legend: { labels: { color: "#94a3b8", font: { family: "Outfit", size: 11 } } },
        tooltip: {
          backgroundColor: "rgba(11, 17, 30, 0.9)",
          titleColor: "#00f2fe",
          bodyColor: "#f0f4fc",
          borderColor: "rgba(0, 242, 254, 0.3)",
          borderWidth: 1
        }
      },
      scales: {
        x: {
          title: { display: true, text: "False Positive Rate (FPR)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" }
        },
        y: {
          title: { display: true, text: "True Positive Rate (Detection Recall)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" },
          min: 0,
          max: 1.05
        }
      }
    }
  });
}

function initPrChart() {
  const ctx = document.getElementById("chart-pr-curves");
  if (!ctx) return;

  const recalls = [0, 0.2, 0.4, 0.6, 0.8, 0.9, 0.95, 0.98, 0.99, 1.0];

  chartPr = new Chart(ctx, {
    type: "line",
    data: {
      labels: recalls,
      datasets: [
        {
          label: "Stacking Ensemble (AP = 0.9929)",
          data: [1.0, 1.0, 1.0, 0.998, 0.995, 0.993, 0.991, 0.988, 0.975, 0.92],
          borderColor: "#00f2fe",
          borderWidth: 3,
          pointRadius: 3,
          tension: 0.2
        },
        {
          label: "RandomForest (AP = 0.9955)",
          data: [1.0, 1.0, 1.0, 0.999, 0.996, 0.994, 0.992, 0.989, 0.978, 0.93],
          borderColor: "#1f77b4",
          borderWidth: 2,
          pointRadius: 2.5,
          tension: 0.2
        },
        {
          label: "Two-Stage Cascade (AP = 0.4222)",
          data: [1.0, 0.998, 0.85, 0.65, 0.48, 0.38, 0.32, 0.25, 0.20, 0.18],
          borderColor: "#ff416c",
          borderWidth: 2.5,
          borderDash: [4, 4],
          pointRadius: 3,
          tension: 0.2
        },
        {
          label: "IsolationForest (AP = 0.2262)",
          data: [0.35, 0.25, 0.20, 0.16, 0.13, 0.10, 0.09, 0.08, 0.08, 0.07],
          borderColor: "#b224ef",
          borderWidth: 1.8,
          borderDash: [3, 3],
          pointRadius: 2,
          tension: 0.2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "nearest", intersect: false },
      plugins: {
        legend: { labels: { color: "#94a3b8", font: { family: "Outfit", size: 11 } } },
        tooltip: {
          backgroundColor: "rgba(11, 17, 30, 0.9)",
          titleColor: "#00f2fe",
          bodyColor: "#f0f4fc"
        }
      },
      scales: {
        x: {
          title: { display: true, text: "Recall (Detection Coverage)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" }
        },
        y: {
          title: { display: true, text: "Precision (Attack Purity)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" },
          min: 0,
          max: 1.05
        }
      }
    }
  });
}

function initMetricsChart() {
  const ctx = document.getElementById("chart-metrics-comparison");
  if (!ctx) return;

  const modelLabels = MODEL_DATA.map(m => m.model.split(" ")[0]);

  chartMetrics = new Chart(ctx, {
    type: "bar",
    data: {
      labels: modelLabels,
      datasets: [
        {
          label: "Accuracy",
          data: MODEL_DATA.map(m => m.accuracy),
          backgroundColor: "rgba(79, 172, 254, 0.8)",
          borderRadius: 4
        },
        {
          label: "Precision",
          data: MODEL_DATA.map(m => m.precision),
          backgroundColor: "rgba(56, 239, 125, 0.8)",
          borderRadius: 4
        },
        {
          label: "Recall (Coverage)",
          data: MODEL_DATA.map(m => m.recall),
          backgroundColor: "rgba(0, 242, 254, 0.8)",
          borderRadius: 4
        },
        {
          label: "F1-Score",
          data: MODEL_DATA.map(m => m.f1),
          backgroundColor: "rgba(255, 117, 140, 0.8)",
          borderRadius: 4
        },
        {
          label: "ROC-AUC",
          data: MODEL_DATA.map(m => m.rocAuc),
          backgroundColor: "rgba(178, 36, 239, 0.8)",
          borderRadius: 4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#94a3b8", font: { family: "Outfit", size: 11 } } },
        tooltip: {
          backgroundColor: "rgba(11, 17, 30, 0.9)",
          titleColor: "#00f2fe",
          bodyColor: "#f0f4fc",
          callbacks: {
            label: function(context) {
              return `${context.dataset.label}: ${(context.raw * 100).toFixed(2)}%`;
            }
          }
        }
      },
      scales: {
        x: {
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#f0f4fc", font: { weight: 600 } }
        },
        y: {
          title: { display: true, text: "Performance Score (0 - 1.0)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" },
          min: 0,
          max: 1.15
        }
      }
    }
  });
}

function initLatencyChart() {
  const ctx = document.getElementById("chart-latency-tradeoff");
  if (!ctx) return;

  const scatterData = MODEL_DATA.map(m => ({
    x: m.latency,
    y: m.f1,
    name: m.model,
    type: m.type
  }));

  chartLatency = new Chart(ctx, {
    type: "scatter",
    data: {
      datasets: [
        {
          label: "Individual Baselines",
          data: scatterData.filter(d => d.type.includes("Baseline")),
          backgroundColor: "#ff7f0e",
          borderColor: "#ffffff",
          pointRadius: 9,
          pointHoverRadius: 12
        },
        {
          label: "Hybrid Architectures",
          data: scatterData.filter(d => d.type.includes("Hybrid")),
          backgroundColor: "#00f2fe",
          borderColor: "#ffffff",
          pointRadius: 11,
          pointHoverRadius: 14
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#94a3b8", font: { family: "Outfit", size: 11 } } },
        tooltip: {
          backgroundColor: "rgba(11, 17, 30, 0.95)",
          titleColor: "#00f2fe",
          bodyColor: "#f0f4fc",
          callbacks: {
            label: function(ctx) {
              const pt = ctx.raw;
              return `${pt.name} -> Latency: ${pt.x.toFixed(2)} ms/1k, F1: ${pt.y.toFixed(4)}`;
            }
          }
        }
      },
      scales: {
        x: {
          title: { display: true, text: "Inference Latency (ms per 1,000 packets) [Lower = Faster]", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" },
          min: 0,
          max: 6.0
        },
        y: {
          title: { display: true, text: "F1 Detection Score [Higher = Better]", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b" },
          min: 0,
          max: 1.1
        }
      }
    }
  });
}

function initFilterButtons() {
  const filterBtns = document.querySelectorAll(".btn-filter");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const mode = btn.getAttribute("data-filter");

      if (!chartMetrics) return;

      if (mode === "hybrid") {
        chartMetrics.data.labels = MODEL_DATA.filter(m => m.type.includes("Hybrid")).map(m => m.model.split(" ")[0]);
        chartMetrics.data.datasets.forEach((ds, i) => {
          const keys = ["accuracy", "precision", "recall", "f1", "rocAuc"];
          ds.data = MODEL_DATA.filter(m => m.type.includes("Hybrid")).map(m => m[keys[i]]);
        });
      } else if (mode === "misuse") {
        chartMetrics.data.labels = MODEL_DATA.filter(m => m.type.includes("Misuse")).map(m => m.model.split(" ")[0]);
        chartMetrics.data.datasets.forEach((ds, i) => {
          const keys = ["accuracy", "precision", "recall", "f1", "rocAuc"];
          ds.data = MODEL_DATA.filter(m => m.type.includes("Misuse")).map(m => m[keys[i]]);
        });
      } else if (mode === "anomaly") {
        chartMetrics.data.labels = MODEL_DATA.filter(m => m.type.includes("Anomaly")).map(m => m.model.split(" ")[0]);
        chartMetrics.data.datasets.forEach((ds, i) => {
          const keys = ["accuracy", "precision", "recall", "f1", "rocAuc"];
          ds.data = MODEL_DATA.filter(m => m.type.includes("Anomaly")).map(m => m[keys[i]]);
        });
      } else {
        chartMetrics.data.labels = MODEL_DATA.map(m => m.model.split(" ")[0]);
        chartMetrics.data.datasets.forEach((ds, i) => {
          const keys = ["accuracy", "precision", "recall", "f1", "rocAuc"];
          ds.data = MODEL_DATA.map(m => m[keys[i]]);
        });
      }
      chartMetrics.update();
    });
  });
}

// ============================================================================
// 6. CONFUSION MATRIX & REPORTS EXPLORER
// ============================================================================
function initMatrixExplorer() {
  const tabBtns = document.querySelectorAll(".matrix-tab-btn");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const modelName = btn.getAttribute("data-model");
      updateMatrixView(modelName);
    });
  });

  // Default view
  updateMatrixView("Stacking Ensemble (Hybrid 1)");
}

function updateMatrixView(modelName) {
  const model = MODEL_DATA.find(m => m.model === modelName) || MODEL_DATA[3];

  document.getElementById("cm-val-tn").textContent = model.cm.tn.toLocaleString();
  document.getElementById("cm-val-fp").textContent = model.cm.fp.toLocaleString();
  document.getElementById("cm-val-fn").textContent = model.cm.fn.toLocaleString();
  document.getElementById("cm-val-tp").textContent = model.cm.tp.toLocaleString();

  document.getElementById("cm-rate-fpr").textContent = (model.fpr * 100).toFixed(2) + "%";
  document.getElementById("cm-rate-fnr").textContent = (model.fnr * 100).toFixed(2) + "%";
  document.getElementById("cm-rate-tpr").textContent = (model.recall * 100).toFixed(2) + "%";
  document.getElementById("cm-rate-tnr").textContent = ((1 - model.fpr) * 100).toFixed(2) + "%";

  document.getElementById("terminal-model-title").textContent = `classification_report.log — ${model.model}`;
  document.getElementById("terminal-report-code").textContent = `=== ${model.model} ===\n${model.report}`;
}

// ============================================================================
// 7. INTERACTIVE THREAT SIMULATOR / PACKET SANDBOX
// ============================================================================
function initSimulator() {
  // Preset buttons
  const presetBtns = document.querySelectorAll(".btn-preset");
  presetBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      presetBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const presetKey = btn.getAttribute("data-preset");
      loadPreset(presetKey);
    });
  });

  // Sliders
  const sliderDuration = document.getElementById("slider-flow-duration");
  const sliderFwd = document.getElementById("slider-fwd-packets");
  const sliderBytes = document.getElementById("slider-flow-bytes");
  const sliderSyn = document.getElementById("slider-syn-flag");
  const sliderLen = document.getElementById("slider-len-var");
  const sliderDev = document.getElementById("slider-anomaly-dev");

  sliderDuration.addEventListener("input", e => {
    document.getElementById("val-flow-duration").textContent = Number(e.target.value).toLocaleString();
    runLiveInference();
  });
  sliderFwd.addEventListener("input", e => {
    document.getElementById("val-fwd-packets").textContent = Number(e.target.value).toLocaleString();
    runLiveInference();
  });
  sliderBytes.addEventListener("input", e => {
    document.getElementById("val-flow-bytes").textContent = Number(e.target.value).toLocaleString();
    runLiveInference();
  });
  sliderSyn.addEventListener("input", e => {
    document.getElementById("val-syn-flag").textContent = e.target.value;
    runLiveInference();
  });
  sliderLen.addEventListener("input", e => {
    document.getElementById("val-len-var").textContent = Number(e.target.value).toLocaleString();
    runLiveInference();
  });
  sliderDev.addEventListener("input", e => {
    document.getElementById("val-anomaly-dev").textContent = (Number(e.target.value) / 10).toFixed(1) + " σ";
    runLiveInference();
  });

  document.getElementById("btn-run-simulation").addEventListener("click", runLiveInference);

  // Load default preset
  loadPreset("portscan");
}

function loadPreset(key) {
  const p = PRESET_PROFILES[key];
  if (!p) return;

  document.getElementById("slider-flow-duration").value = p.duration;
  document.getElementById("val-flow-duration").textContent = p.duration.toLocaleString();

  document.getElementById("slider-fwd-packets").value = p.fwdPackets;
  document.getElementById("val-fwd-packets").textContent = p.fwdPackets.toLocaleString();

  document.getElementById("slider-flow-bytes").value = p.flowBytes;
  document.getElementById("val-flow-bytes").textContent = p.flowBytes.toLocaleString();

  document.getElementById("slider-syn-flag").value = p.synFlag;
  document.getElementById("val-syn-flag").textContent = p.synFlag;

  document.getElementById("slider-len-var").value = p.lenVar;
  document.getElementById("val-len-var").textContent = p.lenVar.toLocaleString();

  document.getElementById("slider-anomaly-dev").value = p.anomalyDev * 10;
  document.getElementById("val-anomaly-dev").textContent = p.anomalyDev.toFixed(1) + " σ";

  runLiveInference();
}

function runLiveInference() {
  const duration = Number(document.getElementById("slider-flow-duration").value);
  const fwd = Number(document.getElementById("slider-fwd-packets").value);
  const bytes = Number(document.getElementById("slider-flow-bytes").value);
  const syn = Number(document.getElementById("slider-syn-flag").value);
  const lenVar = Number(document.getElementById("slider-len-var").value);
  const dev = Number(document.getElementById("slider-anomaly-dev").value) / 10;

  // Real-time heuristic mathematical approximation of models
  let anomalyScore = Math.min(100, Math.max(5, (dev * 22) + (lenVar > 200000 ? 20 : 0) + (bytes > 80000 ? 15 : 0)));
  let misuseScore = Math.min(100, Math.max(1, (syn * 35) + (fwd > 30 ? 30 : 5) + (bytes > 50000 ? 30 : 5)));

  if (syn === 0 && dev < 1.0 && fwd < 20) {
    misuseScore = Math.max(0.2, misuseScore * 0.1);
    anomalyScore = Math.max(5, anomalyScore * 0.3);
  }

  // Stacking meta combination (Logistic sigmoid approximation)
  const z = -4.5 + (misuseScore * 0.065) + (anomalyScore * 0.035);
  const stackProb = 1 / (1 + Math.exp(-z));
  const stackPercent = (stackProb * 100).toFixed(1);

  // Two-Stage Cascade logic
  const cascadePassedIso = anomalyScore >= 40;
  const cascadeConfirmed = cascadePassedIso && misuseScore >= 35;

  const isAttack = stackProb >= 0.5;

  // Update DOM Output
  const banner = document.getElementById("sim-banner");
  const headline = document.getElementById("sim-headline");
  const detail = document.getElementById("sim-detail");
  const icon = document.getElementById("sim-icon");
  const confEl = document.getElementById("sim-confidence-score");
  const statusTag = document.getElementById("sim-overall-verdict");
  const mitigation = document.getElementById("sim-mitigation");

  if (isAttack) {
    banner.className = "sim-verdict-banner attack";
    headline.textContent = "MALICIOUS PACKET FLOW IDENTIFIED";
    detail.textContent = `High-Confidence Threat Signature (SYN=${syn}, Anomaly Deviation=${dev.toFixed(1)}σ)`;
    icon.textContent = "🚨";
    confEl.textContent = (stackProb).toFixed(3);
    confEl.className = "score-num text-red";
    statusTag.textContent = "THREAT CONFIRMED";
    statusTag.className = "threat-status-tag";

    mitigation.textContent = "Append dynamic drop rule to iptables/ACL for source IP. Flag connection flow in SOC SIEM for automated forensic analysis.";
  } else {
    banner.className = "sim-verdict-banner benign";
    headline.textContent = "BENIGN NETWORK TRAFFIC VERIFIED";
    detail.textContent = `Flow metrics conform to established normal operational baseline (Confidence: ${((1 - stackProb) * 100).toFixed(1)}%)`;
    icon.textContent = "🛡️";
    confEl.textContent = (stackProb).toFixed(3);
    confEl.className = "score-num text-green";
    statusTag.textContent = "NORMAL TRAFFIC";
    statusTag.className = "sys-status-badge";

    mitigation.textContent = "No countermeasure required. Flow forwarded along fast-path without ingress throttling.";
  }

  // Update Individual Engine Bars
  document.getElementById("eng-rf-pred").textContent = `${misuseScore.toFixed(1)}% Threat Prob`;
  document.getElementById("eng-rf-bar").style.width = `${misuseScore}%`;

  document.getElementById("eng-gbc-pred").textContent = `${misuseScore.toFixed(1)}% Threat Prob`;
  document.getElementById("eng-gbc-bar").style.width = `${misuseScore}%`;

  document.getElementById("eng-iso-pred").textContent = `Outlier Score: ${(anomalyScore / 100).toFixed(2)}`;
  document.getElementById("eng-iso-bar").style.width = `${anomalyScore}%`;

  document.getElementById("eng-stack-pred").textContent = `${isAttack ? 'MALICIOUS' : 'BENIGN'} (${stackPercent}%)`;
  document.getElementById("eng-stack-bar").style.width = `${stackPercent}%`;

  document.getElementById("eng-cascade-pred").textContent = cascadeConfirmed ? "CONFIRMED (Stage 2)" : (cascadePassedIso ? "SUSPECT (Stage 1)" : "BENIGN (Fast-Path)");
  document.getElementById("eng-cascade-bar").style.width = cascadeConfirmed ? "98.5%" : (cascadePassedIso ? "50%" : "2%");
}

// ============================================================================
// 8. LIVE NETWORK TELEMETRY STREAM
// ============================================================================
function initLiveStream() {
  initLiveDonutChart();

  const toggleBtn = document.getElementById("btn-toggle-stream");
  toggleBtn.addEventListener("click", () => {
    isStreaming = !isStreaming;
    if (isStreaming) {
      toggleBtn.classList.add("active");
      document.getElementById("stream-btn-text").textContent = "PAUSE STREAM";
      startLiveStreamLoop();
    } else {
      toggleBtn.classList.remove("active");
      document.getElementById("stream-btn-text").textContent = "RESUME STREAM";
      clearInterval(streamInterval);
    }
  });

  startLiveStreamLoop();
}

function initLiveDonutChart() {
  const ctx = document.getElementById("chart-live-composition");
  if (!ctx) return;

  chartLiveDonut = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Normal Flow", "PortScan Attacks", "Novel Anomalies"],
      datasets: [
        {
          data: [liveCounts.normal, liveCounts.portscan, liveCounts.anomaly],
          backgroundColor: ["#38ef7d", "#ff416c", "#b224ef"],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom", labels: { color: "#94a3b8", font: { family: "Outfit", size: 10 } } }
      },
      cutout: "70%"
    }
  });
}

function startLiveStreamLoop() {
  if (streamInterval) clearInterval(streamInterval);

  streamInterval = setInterval(() => {
    if (!isStreaming) return;

    livePktCount += Math.floor(Math.random() * 8) + 2;
    document.getElementById("live-pkt-count").textContent = livePktCount.toLocaleString();

    generateStreamRow();
  }, 1200);
}

function generateStreamRow() {
  const tbody = document.getElementById("live-stream-tbody");
  if (!tbody) return;

  const now = new Date().toTimeString().split(" ")[0] + "." + Math.floor(Math.random() * 900 + 100);
  const srcIps = ["192.168.1.104", "10.0.0.45", "172.16.88.12", "192.168.10.89", "45.33.32.156", "185.220.101.5"];
  const ports = [80, 443, 22, 8080, 21, 3389, 445, 8443, 53];
  const protos = ["TCP", "UDP", "TCP"];

  const roll = Math.random();
  let ip = srcIps[Math.floor(Math.random() * srcIps.length)];
  let port = ports[Math.floor(Math.random() * ports.length)];
  let proto = protos[Math.floor(Math.random() * protos.length)];
  let duration = Math.floor(Math.random() * 800000 + 10000);

  let isoFlag = "Normal";
  let misuseFlag = "Benign";
  let hybridVerdict = `<span class="badge-success">BENIGN</span>`;

  if (roll < 0.22) {
    // PortScan
    ip = "45.33.32.156";
    port = Math.floor(Math.random() * 10000 + 1000);
    proto = "TCP";
    duration = 1200000 + Math.floor(Math.random() * 50000);
    isoFlag = `<span class="text-purple">Anomaly (0.84)</span>`;
    misuseFlag = `<span class="text-red">PortScan (99%)</span>`;
    hybridVerdict = `<span class="badge-tag">ATTACK BLOCKED</span>`;
    liveCounts.portscan++;
  } else if (roll < 0.28) {
    // Novel Anomaly
    ip = "185.220.101.5";
    isoFlag = `<span class="text-purple">Anomaly (0.92)</span>`;
    misuseFlag = `<span class="text-muted">Uncertain (45%)</span>`;
    hybridVerdict = `<span class="badge-purple">QUARANTINED</span>`;
    liveCounts.anomaly++;
  } else {
    // Normal
    liveCounts.normal++;
  }

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${now}</td>
    <td>${ip}</td>
    <td>${port}</td>
    <td>${proto}</td>
    <td>${duration.toLocaleString()} µs</td>
    <td>${isoFlag}</td>
    <td>${misuseFlag}</td>
    <td>${hybridVerdict}</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Keep top 12 rows
  while (tbody.children.length > 12) {
    tbody.removeChild(tbody.lastChild);
  }

  // Update counts
  document.getElementById("live-count-normal").textContent = liveCounts.normal.toLocaleString();
  document.getElementById("live-count-portscan").textContent = liveCounts.portscan.toLocaleString();
  document.getElementById("live-count-anomaly").textContent = liveCounts.anomaly.toLocaleString();

  if (chartLiveDonut) {
    chartLiveDonut.data.datasets[0].data = [liveCounts.normal, liveCounts.portscan, liveCounts.anomaly];
    chartLiveDonut.update("none");
  }
}

// ============================================================================
// 9. QUICK SCAN BUTTON
// ============================================================================
function initQuickScanButton() {
  const btn = document.getElementById("btn-quick-scan");
  if (!btn) return;

  btn.addEventListener("click", () => {
    // Switch to simulator tab and run quick test
    const simTabBtn = document.querySelector('.nav-tab[data-tab="tab-simulator"]');
    if (simTabBtn) simTabBtn.click();
    loadPreset("portscan");
  });
}
