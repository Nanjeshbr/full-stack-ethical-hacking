require("dotenv").config();

const path    = require("path");
const express = require("express");
const axios   = require("axios");
const cors    = require("cors");
const rateLimit = require("express-rate-limit");
const db      = require("./db");

const app = express();

// ── CONFIG ───────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
const ZAP  = process.env.ZAP_URL || "http://localhost:8080";

// ── CORS ────────────────────────────────────────────────
app.use(cors({
  origin: [
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "null"           // allows file:// opened pages
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

app.use(express.json());

// ── RATE LIMITING ───────────────────────────────────────
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests. Please wait a minute before trying again." }
});

// ── SERVE FRONTEND ──────────────────────────────────────
const frontendPath = path.join(__dirname, "../frontend");
app.use(express.static(frontendPath));

// ── HEALTH CHECK ────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok" }));
app.get("/api",    (req, res) => res.json({ status: "ok", message: "Security Audit Backend is running." }));

// ── URL VALIDATION ──────────────────────────────────────
function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// ── SEVERITY SORT ORDER ─────────────────────────────────
function severityOrder(s) {
  if (!s) return 4;
  const l = s.toLowerCase();
  if (l === "high")   return 1;
  if (l === "medium" || l === "moderate") return 2;
  if (l === "low")    return 3;
  return 4;
}

// ═══════════════════════════════════════════════════════
//  STANDALONE SECURITY CHECKS  (no ZAP needed)
// ═══════════════════════════════════════════════════════
async function runStandaloneChecks(url) {
  const vulns = [];

  // 1. Missing HTTPS
  if (url.startsWith("http://")) {
    vulns.push({
      name: "Missing HTTPS",
      description:
        "The website uses plain HTTP. All data is transmitted unencrypted, " +
        "making it vulnerable to eavesdropping and man-in-the-middle attacks.",
      severity: "High"
    });
  }

  // Fetch the page (follow redirects, capture headers)
  let response = null;
  try {
    response = await axios.get(url, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true,          // accept any HTTP status
      headers: { "User-Agent": "SecurityAuditBot/1.0" }
    });
  } catch (err) {
    vulns.push({
      name: "Site Unreachable",
      description: `Could not connect to ${url}. Error: ${err.message}`,
      severity: "High"
    });
    return vulns;   // no point checking headers if site is down
  }

  const headers = response.headers || {};

  // 2. Missing HTTP Strict Transport Security
  if (!headers["strict-transport-security"]) {
    vulns.push({
      name: "Missing Strict-Transport-Security (HSTS)",
      description:
        "The server does not send the Strict-Transport-Security header. " +
        "This allows downgrade attacks that force the browser to use HTTP.",
      severity: "Medium"
    });
  }

  // 3. Missing Content-Security-Policy
  if (!headers["content-security-policy"]) {
    vulns.push({
      name: "Missing Content-Security-Policy (CSP)",
      description:
        "No Content-Security-Policy header was found. Without CSP, the site " +
        "is more vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
      severity: "Medium"
    });
  }

  // 4. Missing X-Frame-Options (Clickjacking)
  if (!headers["x-frame-options"] && !headers["content-security-policy"]?.toLowerCase().includes("frame-ancestors")) {
    vulns.push({
      name: "Missing X-Frame-Options (Clickjacking Risk)",
      description:
        "The X-Frame-Options header is absent. Attackers can embed the page " +
        "in an invisible iframe to trick users into unintended clicks (clickjacking).",
      severity: "Medium"
    });
  }

  // 5. Missing X-Content-Type-Options
  if (!headers["x-content-type-options"]) {
    vulns.push({
      name: "Missing X-Content-Type-Options",
      description:
        "The X-Content-Type-Options: nosniff header is missing. Browsers may " +
        "MIME-sniff responses, enabling certain cross-site scripting attacks.",
      severity: "Low"
    });
  }

  // 6. Missing X-XSS-Protection (legacy but still checked)
  if (!headers["x-xss-protection"]) {
    vulns.push({
      name: "Missing X-XSS-Protection",
      description:
        "The X-XSS-Protection header is not set. While modern browsers rely on " +
        "CSP instead, older browsers benefit from this extra layer of protection.",
      severity: "Low"
    });
  }

  // 7. Missing Referrer-Policy
  if (!headers["referrer-policy"]) {
    vulns.push({
      name: "Missing Referrer-Policy",
      description:
        "No Referrer-Policy header was found. The browser may send the full URL " +
        "in the Referer header to third parties, leaking sensitive path information.",
      severity: "Low"
    });
  }

  // 8. Missing Permissions-Policy
  if (!headers["permissions-policy"] && !headers["feature-policy"]) {
    vulns.push({
      name: "Missing Permissions-Policy",
      description:
        "The Permissions-Policy (formerly Feature-Policy) header is absent. " +
        "This header controls access to browser features like camera, microphone, " +
        "and geolocation.",
      severity: "Low"
    });
  }

  // 9. Server header leaking version info
  const serverHeader = headers["server"] || "";
  if (serverHeader && /[\d.]/.test(serverHeader)) {
    vulns.push({
      name: "Server Version Disclosure",
      description:
        `The Server header reveals software version information: "${serverHeader}". ` +
        "This helps attackers identify known vulnerabilities for that specific version.",
      severity: "Low"
    });
  }

  // 10. X-Powered-By leaking tech stack
  if (headers["x-powered-by"]) {
    vulns.push({
      name: "Technology Stack Disclosure (X-Powered-By)",
      description:
        `The X-Powered-By header exposes the backend technology: "${headers["x-powered-by"]}". ` +
        "Attackers can use this to target version-specific exploits.",
      severity: "Low"
    });
  }

  // 11. Cookie security flags
  const rawCookies = response.headers["set-cookie"] || [];
  const cookieList = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
  cookieList.forEach(cookie => {
    if (!cookie) return;
    const cl = cookie.toLowerCase();
    if (!cl.includes("httponly")) {
      vulns.push({
        name: "Cookie Missing HttpOnly Flag",
        description:
          `A cookie is set without the HttpOnly flag: "${cookie.split(";")[0]}". ` +
          "JavaScript can read this cookie, enabling theft via XSS attacks.",
        severity: "Medium"
      });
    }
    if (url.startsWith("https://") && !cl.includes("secure")) {
      vulns.push({
        name: "Cookie Missing Secure Flag",
        description:
          `A cookie is set without the Secure flag: "${cookie.split(";")[0]}". ` +
          "The cookie can be transmitted over plain HTTP, exposing session tokens.",
        severity: "Medium"
      });
    }
    if (!cl.includes("samesite")) {
      vulns.push({
        name: "Cookie Missing SameSite Attribute",
        description:
          `A cookie is missing the SameSite attribute: "${cookie.split(";")[0]}". ` +
          "This may allow Cross-Site Request Forgery (CSRF) attacks.",
        severity: "Low"
      });
    }
  });

  return vulns;
}

// ═══════════════════════════════════════════════════════
//  OPTIONAL ZAP DEEP SCAN
// ═══════════════════════════════════════════════════════
async function runZapScan(url) {
  try {
    // Stop any old scans
    await axios.get(`${ZAP}/JSON/spider/action/stopAllScans/`, { timeout: 5000 }).catch(() => {});
    await axios.get(`${ZAP}/JSON/ascan/action/stopAllScans/`,  { timeout: 5000 }).catch(() => {});
    await axios.get(`${ZAP}/JSON/core/action/deleteAllAlerts/`, { timeout: 5000 }).catch(() => {});

    // Start spider
    await axios.get(`${ZAP}/JSON/spider/action/scan/?url=${encodeURIComponent(url)}`, { timeout: 10000 });

    // Poll until spider is done (max 30s)
    for (let i = 0; i < 6; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const statusRes = await axios.get(`${ZAP}/JSON/spider/view/status/`, { timeout: 5000 });
      const progress = parseInt(statusRes.data.status || "0", 10);
      if (progress >= 100) break;
    }

    // Fetch ZAP alerts
    const zapRes = await axios.get(
      `${ZAP}/JSON/core/view/alerts/?baseurl=${encodeURIComponent(url)}`,
      { timeout: 10000 }
    );

    // Stop scans in background
    axios.get(`${ZAP}/JSON/spider/action/stopAllScans/`).catch(() => {});
    axios.get(`${ZAP}/JSON/ascan/action/stopAllScans/`).catch(() => {});

    return (zapRes.data.alerts || []).map(a => ({
      name: a.alert,
      description: a.description,
      severity: a.risk
    }));
  } catch (err) {
    const isDown = err.code === "ECONNREFUSED" || err.code === "ECONNRESET";
    console.log(isDown ? "[ZAP] Not running — skipping ZAP scan." : `[ZAP] Error: ${err.message}`);
    return null;   // null = ZAP unavailable
  }
}

// ── SCORE CALCULATOR ────────────────────────────────────
function calcScore(vulns) {
  const high   = vulns.filter(v => v.severity === "High").length;
  const medium = vulns.filter(v => (v.severity === "Medium" || v.severity === "Moderate")).length;
  const low    = vulns.filter(v => v.severity === "Low").length;
  const score  = Math.max(0, Math.min(100, 100 - (high * 10 + medium * 5 + low * 2) / 2));
  return { high, medium, low, score: Math.round(score * 10) / 10 };
}

// ═══════════════════════════════════════════════════════
//  POST /scan  — main endpoint
// ═══════════════════════════════════════════════════════
app.post("/scan", scanLimiter, async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Please provide a website URL." });
  }
  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL. Must start with http:// or https://" });
  }

  // Run standalone checks (always works)
  const standaloneVulns = await runStandaloneChecks(url);

  // Try ZAP (optional — skipped if ZAP is not running)
  const zapVulns = await runZapScan(url);
  const zapActive = zapVulns !== null;

  // Merge results (deduplicate by name)
  const seen  = new Set(standaloneVulns.map(v => v.name));
  const extra = zapActive ? zapVulns.filter(v => !seen.has(v.name)) : [];
  let vulnerabilities = [...standaloneVulns, ...extra];

  // Sort: High → Medium → Low → Informational
  vulnerabilities.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  const { high, medium, low, score: securityScore } = calcScore(vulnerabilities);
  const total = vulnerabilities.length;
  const now   = new Date().toISOString();

  // ── SAVE TO DB ─────────────────────────────────────
  db.run("DELETE FROM vulnerabilities WHERE website = ?", [url], deleteErr => {
    if (deleteErr) {
      console.error("[DB DELETE ERROR]", deleteErr.message);
      return res.status(500).json({ error: "Database error while clearing old results." });
    }

    const stmt = db.prepare(`
      INSERT INTO vulnerabilities (website, name, description, severity, scanned_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    vulnerabilities.forEach(v => stmt.run(url, v.name, v.description, v.severity, now));

    stmt.finalize(insertErr => {
      if (insertErr) {
        console.error("[DB INSERT ERROR]", insertErr.message);
        return res.status(500).json({ error: "Database error while saving results." });
      }

      db.run(
        `INSERT INTO scans (website, total, high, medium, low, score, scanned_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [url, total, high, medium, low, securityScore, now],
        histErr => {
          if (histErr) console.error("[DB HISTORY ERROR]", histErr.message);
        }
      );

      res.json({
        website: url,
        vulnerabilities,
        total,
        high,
        medium,
        low,
        securityScore,
        zapUsed: zapActive
      });
    });
  });
});

// ── GET /vulnerabilities ────────────────────────────────
app.get("/vulnerabilities", (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing url query parameter." });

  db.all(
    `SELECT * FROM vulnerabilities WHERE website = ?
     ORDER BY CASE severity
       WHEN 'High'   THEN 1
       WHEN 'Medium' THEN 2
       WHEN 'Low'    THEN 3
       ELSE 4
     END`,
    [url],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// ── GET /summary ────────────────────────────────────────
app.get("/summary", (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing url query parameter." });

  db.all("SELECT severity FROM vulnerabilities WHERE website = ?", [url], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const { high, medium, low, score: securityScore } = calcScore(rows.map(r => ({ severity: r.severity })));
    res.json({ total: rows.length, high, medium, low, securityScore });
  });
});

// ── GET /history ────────────────────────────────────────
app.get("/history", (req, res) => {
  db.all(
    `SELECT website, total, high, medium, low, score, scanned_at
     FROM scans ORDER BY scanned_at DESC LIMIT 20`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// ── START SERVER ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Security Audit Backend running at http://localhost:${PORT}`);
  console.log(`🔗 ZAP endpoint: ${ZAP} (optional — scans work without ZAP)`);
});