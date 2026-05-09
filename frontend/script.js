/* =============================================
   CONFIG — change this if your backend port differs
   ============================================= */
const API_BASE = "http://localhost:5000";

/* =============================================
   THEME MANAGEMENT
   ============================================= */
(function initTheme() {
  const saved = localStorage.getItem("theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  document.getElementById("themeIcon").textContent = saved === "dark" ? "☀️" : "🌙";
})();

document.getElementById("themeToggle").addEventListener("click", () => {
  const root = document.documentElement;
  const current = root.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
  document.getElementById("themeIcon").textContent = next === "dark" ? "☀️" : "🌙";
});

/* =============================================
   DATE / TIME
   ============================================= */
document.getElementById("date").innerText = new Date().toLocaleString("en-IN", {
  weekday: "short", year: "numeric", month: "short", day: "numeric",
  hour: "2-digit", minute: "2-digit"
});

/* =============================================
   CHART.JS SETUP
   ============================================= */
let vulnChart = null;

function buildChart(high, medium, low) {
  const ctx = document.getElementById("vulnChart").getContext("2d");
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const gridColor = isDark ? "rgba(255,255,255,0.07)" : "rgba(0,0,0,0.06)";
  const labelColor = isDark ? "#8b949e" : "#6b7280";

  if (vulnChart) {
    vulnChart.data.datasets[0].data = [high, medium, low];
    vulnChart.update("active");
    return;
  }

  vulnChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [{
        label: "Vulnerabilities",
        data: [high, medium, low],
        backgroundColor: ["#dc2626", "#f59e0b", "#16a34a"],
        borderRadius: 10,
        borderSkipped: false,
        barThickness: 48,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 900, easing: "easeInOutQuart" },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.parsed.y} vulnerabilities`
          }
        }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: labelColor, font: { family: "Inter", weight: "600" } }
        },
        y: {
          beginAtZero: true,
          ticks: { stepSize: 1, color: labelColor, font: { family: "Inter" } },
          grid: { color: gridColor }
        }
      }
    }
  });
}

/* =============================================
   SVG GAUGE
   ============================================= */
function updateGauge(score) {
  const fill = document.getElementById("gaugeFill");
  const text = document.getElementById("gaugeText");
  const circumference = 2 * Math.PI * 80;
  const offset = circumference - (score / 100) * circumference;

  fill.style.strokeDashoffset = offset;
  text.textContent = score + "%";

  if (score >= 75) fill.style.stroke = "#16a34a";
  else if (score >= 50) fill.style.stroke = "#f59e0b";
  else fill.style.stroke = "#dc2626";
}

/* =============================================
   SHOW RESULTS
   ============================================= */
function showResults(data) {
  document.getElementById("totalVuln").innerText = data.total ?? "—";
  document.getElementById("highCount").innerText = data.high ?? "—";
  document.getElementById("mediumCount").innerText = data.medium ?? "—";
  document.getElementById("lowCount").innerText = data.low ?? "—";

  const score = Math.round(data.securityScore ?? 0);
  const scoreEl = document.getElementById("securityScore");
  if (scoreEl) scoreEl.innerText = score + "%";
  updateGauge(score);

  const msg = document.getElementById("scoreMessage");
  if (score >= 80) {
    msg.textContent = "✅ Your website is well-secured. Keep maintaining security practices!";
    msg.style.color = "var(--score-msg-good)";
  } else if (score >= 50) {
    msg.textContent = "⚠️ Moderate security. Address medium and high vulnerabilities soon.";
    msg.style.color = "var(--medium)";
  } else {
    msg.textContent = "🚨 Critical security issues detected! Immediate action required.";
    msg.style.color = "var(--score-msg-bad)";
  }

  buildChart(data.high ?? 0, data.medium ?? 0, data.low ?? 0);

  const table = document.getElementById("vulnTable");
  table.innerHTML = "";

  if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
    table.innerHTML = `<tr class="empty-row"><td colspan="4">No vulnerabilities found — the site appears secure!</td></tr>`;
    return;
  }

  data.vulnerabilities.forEach((v, i) => {
    const sev = (v.severity || "").toLowerCase();
    let color = "low";
    if (sev === "high") color = "high";
    else if (sev === "medium" || sev === "moderate") color = "medium";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${i + 1}</td>
      <td><strong>${escapeHtml(v.name)}</strong></td>
      <td>${escapeHtml(v.description)}</td>
      <td><span class="status ${color}">${escapeHtml(v.severity)}</span></td>
    `;
    table.appendChild(row);
  });
}

/* =============================================
   URL VALIDATION
   ============================================= */
function isValidUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/* =============================================
   BACKEND HEALTH CHECK
   ============================================= */
async function checkBackend() {
  try {
    const res = await fetch(`${API_BASE}/health`, { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

/* =============================================
   SCAN WEBSITE
   ============================================= */
async function scanWebsite() {
  const urlInput = document.getElementById("websiteUrl");
  const url = urlInput.value.trim();
  const button = document.getElementById("scanBtn");
  const btnText = document.getElementById("scanBtnText");
  const errorEl = document.getElementById("urlError");
  const resultEl = document.getElementById("result");

  errorEl.textContent = "";

  if (!url) {
    errorEl.textContent = "⚠️ Please enter a website URL.";
    urlInput.focus();
    return;
  }

  if (!isValidUrl(url)) {
    errorEl.textContent = "⚠️ Invalid URL. Include http:// or https:// (e.g. https://example.com)";
    urlInput.focus();
    return;
  }

  button.disabled = true;
  btnText.textContent = "Scanning...";

  // Check if backend is reachable before scanning
  resultEl.innerHTML = `<div class="loading"><div class="spinner"></div><span>Checking backend connection…</span></div>`;

  const backendUp = await checkBackend();
  if (!backendUp) {
    resultEl.innerHTML = `
      <div class="result-error">
        ✖ Cannot connect to backend server at <code>${API_BASE}</code>.<br><br>
        <strong>Fix:</strong> Open a terminal in the <code>backend</code> folder and run:<br>
        <code>node server.js</code>
      </div>`;
    button.disabled = false;
    btnText.textContent = "Scan Website";
    return;
  }

  resultEl.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <span>Scanning <strong>${escapeHtml(url)}</strong> for vulnerabilities…</span>
    </div>
  `;

  fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  })
    .then(res => {
      if (!res.ok) return res.json().then(e => Promise.reject(e));
      return res.json();
    })
    .then(data => {
      localStorage.setItem("scanResults", JSON.stringify(data));
      resultEl.innerHTML = `<div class="result-success">✔ Scan completed for <strong>${escapeHtml(url)}</strong></div>`;
      showResults(data);
      loadHistory();
    })
    .catch(err => {
      console.error(err);
      let msg = "✖ Scan failed.";
      if (err && err.error) {
        if (err.error.toLowerCase().includes("zap")) {
          msg = "✖ OWASP ZAP is not running. Please start ZAP on port 8080 and try again.";
        } else {
          msg = "✖ " + err.error;
        }
      } else if (err instanceof TypeError) {
        msg = `✖ Cannot connect to backend at <code>${API_BASE}</code>. Make sure it is running.`;
      }
      resultEl.innerHTML = `<div class="result-error">${msg}</div>`;
    })
    .finally(() => {
      button.disabled = false;
      btnText.textContent = "Scan Website";
    });
}

/* =============================================
   RECENT SCANS HISTORY
   ============================================= */
function loadHistory() {
  fetch(`${API_BASE}/history`)
    .then(res => res.json())
    .then(data => {
      const list = document.getElementById("historyList");
      if (!data || data.length === 0) {
        list.innerHTML = `<p class="history-empty">No scan history available.</p>`;
        return;
      }

      list.innerHTML = data.map(item => {
        const dominant = item.high > 0 ? "high" : item.medium > 0 ? "medium" : item.low > 0 ? "low" : "none";
        const badgeLabel = item.high > 0 ? `🔴 ${item.high} High` : item.medium > 0 ? `🟠 ${item.medium} Med` : item.low > 0 ? `🟢 ${item.low} Low` : "✅ Clean";
        const timeStr = item.scanned_at
          ? new Date(item.scanned_at).toLocaleString("en-IN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
          : "";

        return `
          <div class="history-item" onclick="loadScanForUrl('${escapeHtml(item.website)}')" title="Click to view results for this URL">
            <span class="history-url">🔗 ${escapeHtml(item.website)}</span>
            <span class="history-meta">
              <span class="history-badge badge-${dominant}">${badgeLabel}</span>
              <span class="history-time">${timeStr}</span>
            </span>
          </div>
        `;
      }).join("");
    })
    .catch(() => {
      document.getElementById("historyList").innerHTML =
        `<p class="history-empty">Could not load history. Is the backend running on <code>${API_BASE}</code>?</p>`;
    });
}

function loadScanForUrl(url) {
  fetch(`${API_BASE}/vulnerabilities?url=${encodeURIComponent(url)}`)
    .then(res => res.json())
    .then(rows => {
      const high = rows.filter(r => r.severity === "High").length;
      const medium = rows.filter(r => r.severity === "Medium").length;
      const low = rows.filter(r => r.severity === "Low").length;
      const total = rows.length;
      const securityScore = Math.max(0, 100 - (high * 10 + medium * 5 + low * 2) / 2);
      showResults({ vulnerabilities: rows, high, medium, low, total, securityScore });
      document.getElementById("result").innerHTML =
        `<div class="result-success">📂 Loaded saved results for <strong>${escapeHtml(url)}</strong></div>`;
      window.scrollTo({ top: 0, behavior: "smooth" });
    })
    .catch(() => alert("Could not load results for this URL."));
}

/* =============================================
   EXPORT CSV
   ============================================= */
document.getElementById("exportCsvBtn").addEventListener("click", () => {
  const saved = localStorage.getItem("scanResults");
  if (!saved) { alert("No scan results to export. Run a scan first."); return; }
  const data = JSON.parse(saved);
  if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
    alert("No vulnerabilities to export."); return;
  }

  const header = ["#", "Vulnerability", "Description", "Severity"];
  const rows = data.vulnerabilities.map((v, i) =>
    [i + 1, `"${(v.name || "").replace(/"/g, '""')}"`, `"${(v.description || "").replace(/"/g, '""')}"`, v.severity].join(",")
  );
  const csv = [header.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `security_audit_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
});

/* =============================================
   EXPORT PDF (PRINT)
   ============================================= */
document.getElementById("exportPdfBtn").addEventListener("click", () => {
  window.print();
});

/* =============================================
   SCAN BUTTON + ENTER KEY
   ============================================= */
document.getElementById("scanBtn").addEventListener("click", e => {
  e.preventDefault();
  scanWebsite();
});

document.getElementById("websiteUrl").addEventListener("keydown", e => {
  if (e.key === "Enter") scanWebsite();
});

/* =============================================
   REFRESH HISTORY
   ============================================= */
document.getElementById("refreshHistory").addEventListener("click", loadHistory);

/* =============================================
   INIT — LOAD SAVED RESULTS + HISTORY
   ============================================= */
window.addEventListener("load", () => {
  // Clear stale localStorage data on every fresh page load
  // (sessionStorage flag ensures it only clears once per tab session)
  if (!sessionStorage.getItem("sessionActive")) {
    localStorage.removeItem("scanResults");
    sessionStorage.setItem("sessionActive", "true");
  }

  const saved = localStorage.getItem("scanResults");
  if (saved) {
    try { showResults(JSON.parse(saved)); } catch { }
  }
  loadHistory();
});
/* =============================================
   UTILITY
   ============================================= */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}