import { useState, useEffect } from "react";
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000";

// -- Auth token helpers ----------------------------------------------------
const getToken  = () => localStorage.getItem("osint_token");
const setToken  = (t) => localStorage.setItem("osint_token", t);
const clearToken= () => localStorage.removeItem("osint_token");

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

const IOC_TYPES = [
  { id: "ip",     label: "IP Address",    color: "#3B82F6", bg: "#1e3a5f", text: "#93C5FD" },
  { id: "domain", label: "Domain",        color: "#10B981", bg: "#1a3d2f", text: "#6EE7B7" },
  { id: "hash",   label: "File Hash",     color: "#F59E0B", bg: "#3d2f0a", text: "#FCD34D" },
  { id: "url",    label: "URL",           color: "#F43F5E", bg: "#3d1220", text: "#FDA4AF" },
  { id: "email",  label: "Email Address", color: "#A78BFA", bg: "#2d1f5e", text: "#C4B5FD" },
];

const PLACEHOLDERS = {
  ip:     "Enter IP address, e.g. 8.8.8.8",
  domain: "Enter domain, e.g. malware-c2.ru",
  hash:   "Enter file hash (MD5 / SHA1 / SHA256)",
  url:    "Enter URL, e.g. http://phishing-site.com/login",
  email:  "Enter email address, e.g. attacker@evil.com",
};

const SOURCE_COLORS = {
  VirusTotal:     "#3B82F6",
  AbuseIPDB:      "#EF4444",
  OTX:            "#F59E0B",
  ThreatFox:      "#A78BFA",
  URLScan:        "#10B981",
  GSB:            "#6366F1",
  EmailRep:       "#F43F5E",
  HaveIBeenPwned: "#EC4899",
  Shodan:         "#06B6D4",
  MalwareBazaar:  "#F97316",
  WHOIS:          "#6366F1",
  Disify:         "#10B981",
  MailCheck:      "#22D3EE",
  Emailable:      "#F59E0B",
};

// Exactly 4 canonical source slots per IOC type
// These drive the intelligence sources panel - always shows 4 rows
// Tool matrix - matches backend pipeline exactly per IOC type
const SOURCE_SLOTS = {
  ip:     ["VirusTotal", "AbuseIPDB",    "OTX",     "Shodan",         "ThreatFox"],
  domain: ["VirusTotal", "URLScan",      "GSB",     "OTX",            "WHOIS"],
  url:    ["VirusTotal", "URLScan",      "GSB"],
  hash:   ["VirusTotal", "ThreatFox",    "MalwareBazaar",  "OTX"],
  email:  ["Disify", "MailCheck", "Emailable"],
};

const verdictStyle = (v) => {
  if (v === "malicious")  return { bg: "#2d0f0f", color: "#F87171", border: "#7f1d1d", accent: "#EF4444", label: "Malicious" };
  if (v === "suspicious") return { bg: "#2d1f0a", color: "#FCD34D", border: "#7c3a00", accent: "#F59E0B", label: "Suspicious" };
  return                         { bg: "#0d2d1a", color: "#6EE7B7", border: "#14532d", accent: "#10B981", label: "Benign" };
};

const scoreColor  = (s) => s >= 75 ? "#EF4444" : s >= 45 ? "#F59E0B" : "#10B981";
const sourceBadge = (s) => s >= 75 ? { bg: "#2d0f0f", color: "#F87171" } : s >= 45 ? { bg: "#2d1f0a", color: "#FCD34D" } : { bg: "#0d2d1a", color: "#6EE7B7" };

const CARD   = { background: "#111827", border: "1px solid #1f2937", borderRadius: 16, padding: "22px" };
const PTITLE = { fontSize: 10, fontWeight: 700, color: "#4B5563", letterSpacing: "0.12em", paddingBottom: 12, borderBottom: "1px solid #1f2937", marginBottom: 16, textTransform: "uppercase" };

// Validation rules: returns null if valid, error string if invalid
const IOC_VALIDATORS = {
  ip:     { re: /^\d{1,3}(\.\d{1,3}){3}$/,                     msg: "Invalid IP address - expected format: 192.168.1.1" },
  domain: { re: /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$/, msg: "Invalid domain - expected format: example.com" },
  hash:   { re: /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/, msg: "Invalid hash - expected MD5 (32), SHA1 (40), or SHA256 (64) hex characters" },
  url:    { re: /^https?:\/\/.+\..+/,                            msg: "Invalid URL - must start with http:// or https://" },
  email:  { re: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,               msg: "Invalid email address - expected format: user@example.com" },
};

function validateIOC(value, iocType) {
  const v = value.trim();
  if (!v) return "Please enter a value to analyse.";
  const rule = IOC_VALIDATORS[iocType];
  if (rule && !rule.re.test(v)) return rule.msg;
  return null; // valid
}

function detectIOC(v) {
  const val = v.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return "email";
  if (/^(http|https):\/\//.test(val)) return "url";
  if (/^[a-fA-F0-9]{32,64}$/.test(val)) return "hash";
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain";
  return "ip";
}

function getPivotLinks(ioc, iocType) {
  const enc = encodeURIComponent(ioc);
  const vtUrlId = iocType === "url" ? btoa(ioc).replace(/=+$/, "") : enc;
  const sets = {
    ip: [
      ["VirusTotal",     `https://www.virustotal.com/gui/ip-address/${enc}`],
      ["AbuseIPDB",      `https://www.abuseipdb.com/check/${enc}`],
      ["Shodan",         `https://www.shodan.io/host/${enc}`],
      ["AlienVault OTX", `https://otx.alienvault.com/indicator/ip/${enc}`],
      ["ThreatFox",      `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc}`],
      ["Censys",         `https://search.censys.io/hosts/${enc}`],
    ],
    domain: [
      ["VirusTotal",         `https://www.virustotal.com/gui/domain/${enc}`],
      ["URLScan",            `https://urlscan.io/search/#page.domain:${enc}`],
      ["Google Safe Browse", `https://transparencyreport.google.com/safe-browsing/search?url=${enc}`],
      ["AlienVault OTX",     `https://otx.alienvault.com/indicator/domain/${enc}`],
      ["ThreatFox",          `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc}`],
      ["Whois",              `https://who.is/whois/${enc}`],
    ],
    url: [
      ["VirusTotal",         `https://www.virustotal.com/gui/url/${vtUrlId}`],
      ["URLScan",            `https://urlscan.io/search/#page.domain:${(() => { try { return new URL(ioc).hostname; } catch(e) { return encodeURIComponent(ioc); } })()}`],
      ["Google Safe Browse", `https://transparencyreport.google.com/safe-browsing/search?url=${enc}`],

      ["CheckPhish",         `https://checkphish.ai/url-checker?url=${enc}`],
      ["PhishTank Search",   `https://phishtank.org/search.php?query=${enc}&Search=Search`],
    ],
    email: [
      ["HaveIBeenPwned",    `https://haveibeenpwned.com/account/${enc}`],
      ["Emailable",         `https://emailable.com/`],
      ["EmailRep",          `https://emailrep.io/`],
      ["Hunter",            `https://hunter.io/verify/${enc}`],
      ["IntelligenceX",     `https://intelx.io/?s=${enc}`],
      ["MXToolbox",         `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${enc.split('%40')[1]||enc}`],
    ],
    hash: [
      ["VirusTotal",      `https://www.virustotal.com/gui/file/${enc}`],
      ["MalwareBazaar",  `https://bazaar.abuse.ch/browse.php?search=${enc}`],
      ["ThreatFox",       `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc}`],
      ["Hybrid Analysis", `https://www.hybrid-analysis.com/search?query=${enc}`],
    ],
  };
  return sets[iocType] || sets.ip;
}

function mapResponse(raw, iocType) {
  // Backend already sends only the correct sources per IOC type
  const filtered = { ...(raw.sources || {}) };

  // Backend returns raw_score (0-100) directly; score is CVSS (0-10) kept for compat
  const rawScore = raw.raw_score ?? raw.score ?? 0;
  const score100 = rawScore <= 10 ? Math.round(rawScore * 10) : Math.round(rawScore);

  return {
    ioc:        raw.ioc        || "",
    verdict:    raw.verdict    || "benign",
    score:      score100,
    confidence: raw.confidence ?? 0,
    sources:    filtered,
    tags:       raw.tags       || [],
    geo:        raw.geo        || {},
    mitre:      raw.mitre_tactics || raw.mitre || [],
    owasp:      raw.owasp         || [],
    summary:    raw.summary    || "",
    narrative:   raw.narrative   || raw.ai_narrative || "",
    ai_analysis: raw.ai_analysis || "",
    links:       raw.links       || {},
    raw,
  };
}

function buildSummaryLines(ioc, iocType, d) {
  const lines = [`OSINT on [${ioc}]:`];
  const vt  = d.sources?.VirusTotal;
  const ab  = d.sources?.AbuseIPDB;
  const otx = d.sources?.OTX;
  const tf  = d.sources?.ThreatFox;
  const us  = d.sources?.URLScan;
  const gsb = d.sources?.GSB;
  const er  = d.sources?.EmailRep;

  const hp  = d.sources?.HaveIBeenPwned || d.sources?.HIBP;

  const geo = d.geo || {};

  // Malware name banner - hash IOC only
  if (iocType === "hash") {
    const mb  = d.sources?.MalwareBazaar;
    const name = vt?.name || mb?.malware || tf?.malware || "";
    if (name)             lines.push(`Malware Name: ${name}`);
    if (mb?.file_type)    lines.push(`File Type: ${mb.file_type}`);
    if (mb?.tags?.length) lines.push(`Tags: ${mb.tags.slice(0,5).join(", ")}`);
  }

  // VirusTotal - all IOC types
  if (vt) {
    const det  = vt.detections ?? 0;
    const eng  = vt.engines    ?? 94;
    const org  = vt.org || geo.org || "";
    const cats = vt.categories || "";
    let line   = `VirusTotal: ${det}/${eng}`;
    if (vt.name)   line += ` | ${vt.name}`;
    else if (org)  line += ` | ${org}`;
    else if (cats) line += ` | ${cats}`;
    lines.push(line);
  }

  // AbuseIPDB - IP only
  if (ab && iocType === "ip") {
    const conf  = ab.confidence ?? ab.score ?? 0;
    const isp   = ab.isp   || ab.domain || geo.isp || "";
    const usage = ab.usageType || "";
    let line    = `AbuseIPDB: ${conf}% Confidence`;
    if (isp)   line += ` | ${isp}`;
    if (usage) line += ` | ${usage}`;
    lines.push(line);
  }

  // AlienVault OTX - IP + domain
  if (otx) {
    const pulses = otx.pulses ?? 0;
    const note   = otx.note  || (pulses === 0 ? "Known False Positive" : "");
    let line = `AlienVault: ${pulses} Pulses`;
    if (note) line += ` | ${note}`;
    lines.push(line);
  }

  // ThreatFox - IP + domain + hash
  if (tf && ["ip","domain","hash"].includes(iocType)) {
    const hits    = tf.hits ?? 0;
    const malware = tf.malware || "";
    let line = `ThreatFox: ${hits} Hits`;
    if (malware) line += ` | ${malware}`;
    lines.push(line);
  }

  // URLScan - domain + url
  if (us && ["domain","url"].includes(iocType)) {
    const v = us.verdict || "unknown";
    const s = us.score   ?? 0;
    let line = `URLScan: ${v.charAt(0).toUpperCase()+v.slice(1)}`;
    if (s) line += ` | Score: ${s}`;
    lines.push(line);
  }

  // Google Safe Browsing - domain + url
  if (gsb && ["domain","url"].includes(iocType)) {
    const safe    = gsb.safe ?? true;
    const checked = gsb.checked ?? true;
    const flagged = gsb.flagged ?? (!safe);
    const tt      = gsb.threat_type || "";
    let line;
    if (!checked) {
      line = "Google Safe Browsing: Not checked (API key missing/invalid)";
    } else {
      line = `Google Safe Browsing: ${flagged ? "⚠ FLAGGED UNSAFE" : "Safe"}`;
    }
    if (tt) line += ` | ${tt.replace(/_/g," ")}`;
    lines.push(line);
  }

  // Email sources
  if (iocType === "email") {
    if (er) {
      const rep  = er.reputation || "unknown";
      const susp = er.suspicious ? "Yes" : "No";
      lines.push(`EmailRep: ${rep.charAt(0).toUpperCase()+rep.slice(1)} reputation | Suspicious: ${susp}`);
    }


    const df = d.sources?.Disify;
    if (df) {
      const parts = [];
      if (df.disposable)           parts.push("⚠ DISPOSABLE address");
      if (df.dns_valid === false)  parts.push("No MX/DNS record");
      if (df.format_ok === false)  parts.push("Invalid format");
      if ((df.signals||[]).includes("blacklist_exact")) parts.push("Blacklisted domain");
      lines.push("Disify: " + (parts.length ? parts.join(" | ") : "Valid, non-disposable address"));
    }
    const mc = d.sources?.MailCheck;
    if (mc) {
      if (mc.rate_limited) {
        lines.push("MailCheck: Rate limited - try again in 60 seconds");
      } else {
        const parts = [];
        if (mc.disposable)           parts.push("⚠ DISPOSABLE");
        if (mc.spam)                 parts.push("SPAM domain");
        if (mc.mx_valid === false)   parts.push("No MX record");
        if (mc.role)                 parts.push("Role account");
        if (mc.domain_age < 30)      parts.push(`New domain (${mc.domain_age}d old)`);
        lines.push("MailCheck: " + (parts.length ? parts.join(" | ") : `Valid | Domain age: ${mc.domain_age || "?"}d`));
      }
    }
    const em = d.sources?.Emailable;
    if (em) {
      if (em.no_key) {
        lines.push("Emailable: API key not set - add EMAILABLE_API_KEY to .env");
      } else {
        const parts = [];
        if (em.state)       parts.push(`State: ${em.state}`);
        if (em.disposable)  parts.push("⚠ DISPOSABLE");
        if (em.role)        parts.push("Role account");
        if (em.reason)      parts.push(em.reason.replace(/_/g," "));
        lines.push("Emailable: " + (parts.length ? parts.join(" | ") : `Score: ${em.em_score}/100`));
      }
    }
    const abs = d.sources?.AbstractAPI;
    if (abs && abs.score > 0) {
      const parts = [];
      if (abs.disposable)                       parts.push("⚠ DISPOSABLE");
      if (abs.deliverable === "UNDELIVERABLE")  parts.push("Undeliverable");
      if (abs.mx_found === false)               parts.push("No MX record");
      lines.push("AbstractAPI: " + (parts.length ? parts.join(" | ") : "Valid email"));
    }
    const hun = d.sources?.Hunter;
    if (hun && hun.status) {
      lines.push(`Hunter: ${hun.status}${hun.result ? " | " + hun.result : ""}`);
    }
  }

  // WHOIS (domain)
  if (iocType === "domain" && d.sources?.WHOIS) {
    const w = d.sources.WHOIS;
    let line = "WHOIS:";
    if (w.registrar) line += ` Registrar: ${w.registrar}`;
    if (w.created)   line += ` | Created: ${w.created}`;
    if (w.country)   line += ` | Country: ${w.country}`;
    if (w.score > 0) line += ` | ⚠ New domain (high risk)`;
    lines.push(line);
  }

  // Geo - IP only
  if (iocType === "ip") {
    const country = geo.country_name || geo.country || "";
    const city    = geo.city || "";
    if (country) lines.push(`Location: ${country}${city ? `, ${city}` : ""}`);
    if (geo.isp && !lines.some(l => l.includes(geo.isp)))
      lines.push(`ISP: ${geo.isp}`);
  }



  if (d.tags?.length) lines.push(`Tags: ${d.tags.join(", ")}`);

  return lines;
}

function copySummary(lines) {
  navigator.clipboard?.writeText(lines.join("\n"));
}

// -- DONUT CHART ---------------------------------------------------------------
function PieChart({ data, size = 160, centerLabel = null, centerSub = null }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size/2} cy={size/2} r={size/2-14} fill="none" stroke="#1f2937" strokeWidth="18"/>
        <text x={size/2} y={size/2+5} textAnchor="middle" fontSize="13" fontWeight="700" fill="#374151">-</text>
      </svg>
    );
  }
  const cx = size / 2, cy = size / 2, r = size / 2 - 14;
  let cum = -Math.PI / 2;
  const slices = data.map((d) => {
    const angle = (d.value / total) * 2 * Math.PI;
    const x1 = cx + r * Math.cos(cum), y1 = cy + r * Math.sin(cum);
    cum += angle;
    const x2 = cx + r * Math.cos(cum), y2 = cy + r * Math.sin(cum);
    return { ...d, path: `M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${angle > Math.PI ? 1 : 0},1 ${x2},${y2} Z` };
  });
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {slices.map((s, i) => <path key={i} d={s.path} fill={s.color} opacity={0.9}/>)}
      <circle cx={cx} cy={cy} r={r * 0.46} fill="#111827"/>
      {centerLabel != null && <>
        <text x={cx} y={cy + 6} textAnchor="middle" fontSize="18" fontWeight="700" fill="#F9FAFB">{centerLabel}</text>
        {centerSub && <text x={cx} y={cy + 20} textAnchor="middle" fontSize="9" fill="#6B7280">{centerSub}</text>}
      </>}
    </svg>
  );
}

// -- CONFIDENCE DONUT ----------------------------------------------------------
function ConfidenceDonut({ confidence, size = 120 }) {
  const pct = Math.min(100, Math.max(0, confidence));
  const cx = size / 2, cy = size / 2, r = size / 2 - 12;
  const startAngle = -Math.PI / 2;
  const endAngle   = startAngle + (pct / 100) * 2 * Math.PI;
  const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
  const x2 = cx + r * Math.cos(endAngle),   y2 = cy + r * Math.sin(endAngle);
  const largeArc = pct > 50 ? 1 : 0;
  const col = pct >= 75 ? "#EF4444" : pct >= 45 ? "#F59E0B" : "#10B981";
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1f2937" strokeWidth="12"/>
      {pct > 0 && (
        <path
          d={pct >= 100
            ? `M${cx},${cy - r} A${r},${r} 0 1,1 ${cx - 0.001},${cy - r} Z`
            : `M${x1},${y1} A${r},${r} 0 ${largeArc},1 ${x2},${y2}`}
          fill="none" stroke={col} strokeWidth="12" strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 5px ${col})` }}
        />
      )}
      <text x={cx} y={cy + 6} textAnchor="middle" fontSize="18" fontWeight="800" fill="#F9FAFB">{pct}%</text>
      <text x={cx} y={cy + 20} textAnchor="middle" fontSize="9" fill="#6B7280">CONFIDENCE</text>
    </svg>
  );
}

// -- BAR CHART -----------------------------------------------------------------
function BarChart({ sources, compact = false }) {
  const entries = Object.entries(sources);
  if (!entries.length) return (
    <div style={{ fontSize: 12, color: "#4B5563", padding: "24px 0", textAlign: "center" }}>No source data</div>
  );
  const max = Math.max(...entries.map(([, v]) => v?.score ?? 0), 1);
  const barH    = compact ? 18 : 26;
  const gap     = compact ? 8  : 10;
  const labelW  = compact ? 82 : 92;
  const barMaxW = compact ? 160 : 210;
  const rightW  = 44;
  const height  = entries.length * (barH + gap);
  const fSize   = compact ? "10" : "12";
  const fSizeV  = compact ? "11" : "13";
  return (
    <svg width="100%" viewBox={`0 0 ${labelW + barMaxW + rightW + 12} ${height}`} style={{ overflow: "visible" }}>
      {entries.map(([name, src], i) => {
        const s   = src?.score ?? 0;
        const w   = Math.round((s / max) * barMaxW);
        const y   = i * (barH + gap);
        const col = SOURCE_COLORS[name] || "#888";
        return (
          <g key={name}>
            <text x={labelW - 8} y={y + barH / 2 + 4} textAnchor="end" fontSize={fSize} fill="#9CA3AF">{name}</text>
            <rect x={labelW} y={y} width={barMaxW} height={barH} rx={compact ? 5 : 7} fill="#1f2937"/>
            {s > 0 && <rect x={labelW} y={y} width={w} height={barH} rx={compact ? 5 : 7} fill={col} opacity={0.9} style={{ filter: `drop-shadow(0 0 4px ${col})` }}/>}
            {s === 0 && <rect x={labelW} y={y} width={barMaxW * 0.08} height={barH} rx={compact ? 5 : 7} fill="#10B981" opacity={0.5}/>}
            <text x={labelW + barMaxW + 6} y={y + barH / 2 + 4} fontSize={fSizeV} fontWeight="700" fill="#F9FAFB">
              {s === 0 ? "Clean" : s === 1 && name === "GSB" ? (src?.checked === false ? "N/A" : src?.flagged ? "100" : "Clean") : s === 1 ? "Clean" : s}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// -- SCORE GAUGE ---------------------------------------------------------------
function ScoreGauge({ score, size = 200 }) {
  const cx = size / 2, cy = size / 2 + 14, r = size / 2 - 22;
  const start = Math.PI * 0.78, end = Math.PI * 2.22;
  const angle = start + (score / 100) * (end - start);
  const pt = (a) => ({ x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) });
  const ts = pt(start), te = pt(end), fa = pt(angle);
  const col = scoreColor(score);
  const vs  = verdictStyle(score >= 75 ? "malicious" : score >= 45 ? "suspicious" : "benign");
  return (
    <svg width={size} height={size - 10} viewBox={`0 0 ${size} ${size - 10}`}>
      <path d={`M${ts.x},${ts.y} A${r},${r} 0 1,1 ${te.x},${te.y}`}
        fill="none" stroke="#1f2937" strokeWidth="16" strokeLinecap="round"/>
      {score > 0 && (
        <path d={`M${ts.x},${ts.y} A${r},${r} 0 ${(angle - start) > Math.PI ? 1 : 0},1 ${fa.x},${fa.y}`}
          fill="none" stroke={col} strokeWidth="14" strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${col})` }}/>
      )}
      <circle cx={fa.x} cy={fa.y} r="10" fill={col} style={{ filter: `drop-shadow(0 0 6px ${col})` }}/>
      <circle cx={fa.x} cy={fa.y} r="4"  fill="#111827"/>
      <text x={cx} y={cy - 10} textAnchor="middle" fontSize="46" fontWeight="800" fill="#F9FAFB">{score}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="#4B5563">out of 100</text>
      <text x={cx} y={cy + 34} textAnchor="middle" fontSize="14" fontWeight="700" fill={vs.color}
        style={{ filter: `drop-shadow(0 0 4px ${vs.accent})` }}>{vs.label.toUpperCase()}</text>
      <text x={size * 0.04} y={cy + 26} textAnchor="start"  fontSize="9" fontWeight="700" fill="#10B981">LOW</text>
      <text x={size * 0.96} y={cy + 26} textAnchor="end"    fontSize="9" fontWeight="700" fill="#EF4444">HIGH</text>
    </svg>
  );
}

// -- VERDICT BANNER ------------------------------------------------------------
function VerdictBanner({ verdict, score }) {
  const vs = verdictStyle(verdict);
  const messages = {
    malicious:  "High threat activity detected. Immediate action recommended.",
    suspicious: "Suspicious patterns observed. Further investigation advised.",
    benign:     "No significant threats detected. Continue monitoring.",
  };
  return (
    <div style={{ background: vs.bg, border: `1px solid ${vs.border}`, borderRadius: 14, padding: "18px 24px", display: "flex", alignItems: "center", gap: 16, boxShadow: `0 0 24px ${vs.accent}22` }}>
      <div style={{ width: 48, height: 48, borderRadius: 12, background: vs.accent + "22", border: `1px solid ${vs.accent}55`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          {verdict === "malicious"  && <><circle cx="12" cy="12" r="10" fill={vs.accent} opacity="0.3"/><path d="M12 8v4M12 16h.01" stroke={vs.color} strokeWidth="2.5" strokeLinecap="round"/></>}
          {verdict === "suspicious" && <><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" fill={vs.accent} opacity="0.3"/><path d="M12 9v4M12 17h.01" stroke={vs.color} strokeWidth="2.5" strokeLinecap="round"/></>}
          {(verdict === "benign" || !verdict || (verdict !== "malicious" && verdict !== "suspicious")) && <><circle cx="12" cy="12" r="10" fill={vs.accent} opacity="0.3"/><path d="M9 12l2 2 4-4" stroke={vs.color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/></>}
        </svg>
      </div>
      <div>
        <div style={{ fontSize: 16, fontWeight: 800, color: vs.color }}>{vs.label} - Risk Score {score}/100</div>
        <div style={{ fontSize: 13, color: vs.color, opacity: 0.75, marginTop: 3 }}>{messages[verdict] || messages.benign}</div>
      </div>

    </div>
  );
}

// -- DOWNLOAD REPORT -----------------------------------------------------------
function downloadReport(ioc, iocType, d, summaryLines) {
  const aiAnalysis = d.ai_analysis || "";
  const analystAssessment = d.summary || "";
  const vs  = verdictStyle(d.verdict);
  const now = new Date().toLocaleString();
  const sc  = d.score ?? 0;
  const col = scoreColor(sc);

  const srcRows = Object.entries(d.sources || {}).map(([name, src]) => {
    const s = src?.score ?? 0;
    const b = sourceBadge(s);
    const lnk = src?.link ? `<a href="${src.link}" style="color:#3B82F6;font-size:12px;">View →</a>` : "";
    return `<tr><td style="padding:10px 14px;border-bottom:1px solid #1f2937;font-size:13px;color:#D1D5DB;">${name}</td><td style="padding:10px 14px;border-bottom:1px solid #1f2937;"><span style="background:${b.bg};color:${b.color};padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;">${s}/100</span></td><td style="padding:10px 14px;border-bottom:1px solid #1f2937;">${lnk}</td></tr>`;
  }).join("");
  const geoRows   = Object.entries(d.geo   || {}).map(([k, v]) => `<tr><td style="padding:8px 14px;color:#6B7280;font-size:13px;border-bottom:1px solid #111827;width:140px;">${k}</td><td style="padding:8px 14px;font-size:13px;color:#F9FAFB;border-bottom:1px solid #111827;">${v}</td></tr>`).join("");
  const mitreRows = (d.mitre || []).map((m) => `<tr><td style="padding:8px 14px;font-size:12px;color:#3B82F6;border-bottom:1px solid #111827;">${m.id||""}</td><td style="padding:8px 14px;font-size:12px;color:#D1D5DB;border-bottom:1px solid #111827;">${m.name||m}</td></tr>`).join("");
  const summBlock = summaryLines.map((l, i) => i === 0 ? `<div style="font-size:16px;font-weight:700;color:#F9FAFB;margin-bottom:10px;">${l}</div>` : `<div style="font-size:13px;font-family:monospace;color:#9CA3AF;padding:5px 0;border-bottom:1px solid #1f2937;">${l}</div>`).join("");

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>OSINT Report - ${ioc}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;padding:32px;color:#F9FAFB;}.page{max-width:960px;margin:0 auto;background:#111827;border-radius:16px;border:1px solid #1f2937;overflow:hidden;}.hdr{background:#0C447C;padding:30px 36px;}.hdr h1{font-size:22px;font-weight:700;margin-bottom:5px;color:white;}.hdr p{font-size:12px;color:rgba(255,255,255,.6);}.banner{padding:14px 36px;background:${vs.bg};border-bottom:1px solid ${vs.border};font-size:14px;font-weight:700;color:${vs.color};}.metrics{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid #1f2937;}.metric{padding:20px 24px;border-right:1px solid #1f2937;}.metric:last-child{border-right:none;}.ml{font-size:10px;color:#6B7280;margin-bottom:6px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;}.mv{font-size:24px;font-weight:700;color:#F9FAFB;}.sec{padding:24px 36px;border-bottom:1px solid #1f2937;}.sec:last-child{border-bottom:none;}.st{font-size:10px;font-weight:700;color:#4B5563;letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px;}.badge{padding:5px 14px;border-radius:20px;font-size:13px;font-weight:700;background:${vs.bg};color:${vs.color};border:1px solid ${vs.border};}.bar-wrap{background:#1f2937;border-radius:6px;height:10px;overflow:hidden;margin:10px 0 4px;}.bar-fill{height:10px;background:${col};border-radius:6px;width:${sc}%;}table{width:100%;border-collapse:collapse;}.ftr{padding:18px 36px;background:#0d1117;display:flex;justify-content:space-between;font-size:11px;color:#4B5563;}.ai-body{font-size:13px;line-height:1.75;color:#C9D1D9;}.ai-body strong{color:#F9FAFB;font-weight:700;display:block;margin-top:12px;margin-bottom:4px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#3B82F6;}.ai-body br{margin-bottom:2px;}</style></head><body>
<div class="page">
  <div class="hdr"><h1>OSINT Intelligence Report</h1><p>IOC: ${ioc} | Type: ${IOC_TYPES.find(t=>t.id===iocType)?.label||iocType} | ${now}</p></div>
  <div class="banner">${vs.label.toUpperCase()} - Risk Score ${sc}/100</div>
  <div class="metrics">
    <div class="metric"><div class="ml">RISK SCORE</div><div class="mv" style="color:${col};">${sc}/100</div></div>
    <div class="metric"><div class="ml">VERDICT</div><div class="mv"><span class="badge">${vs.label}</span></div></div>
    <div class="metric"><div class="ml">CONFIDENCE</div><div class="mv">${d.confidence??0}%</div></div>
    <div class="metric"><div class="ml">IOC TYPE</div><div class="mv" style="font-size:15px;">${IOC_TYPES.find(t=>t.id===iocType)?.label||iocType}</div></div>
  </div>
  <div class="sec"><div class="st">SUMMARY</div>${summBlock}</div>
  ${srcRows ? `<div class="sec"><div class="st">INTELLIGENCE SOURCES</div><table><thead><tr><th style="text-align:left;padding:8px 14px;font-size:10px;color:#6B7280;border-bottom:1px solid #1f2937;">Source</th><th style="text-align:left;padding:8px 14px;font-size:10px;color:#6B7280;border-bottom:1px solid #1f2937;">Score</th><th style="text-align:left;padding:8px 14px;font-size:10px;color:#6B7280;border-bottom:1px solid #1f2937;">Link</th></tr></thead><tbody>${srcRows}</tbody></table></div>` : ""}
  ${geoRows ? `<div class="sec"><div class="st">GEOLOCATION</div><table><tbody>${geoRows}</tbody></table></div>` : ""}
  ${mitreRows ? `<div class="sec"><div class="st">MITRE ATT&amp;CK</div><table><thead><tr><th style="text-align:left;padding:8px 14px;font-size:10px;color:#6B7280;border-bottom:1px solid #1f2937;">ID</th><th style="text-align:left;padding:8px 14px;font-size:10px;color:#6B7280;border-bottom:1px solid #1f2937;">Technique</th></tr></thead><tbody>${mitreRows}</tbody></table></div>` : ""}
  ${analystAssessment ? `<div class="sec"><div class="st">ANALYST ASSESSMENT</div><pre style="font-size:13px;line-height:1.85;color:#E6EDF3;white-space:pre-wrap;font-family:'Fira Code','JetBrains Mono',monospace;background:#0d1117;padding:18px;border-radius:8px;border:1px solid #1f2937;">${analystAssessment.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</pre></div>` : ""}
  ${aiAnalysis ? `<div class="sec"><div class="st">AI THREAT ANALYSIS</div><div class="ai-body">${aiAnalysis.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br/>")}</div></div>` : ""}
  <div class="ftr"><span>OSINT Intelligence Platform</span><span>${now}</span></div>
</div></body></html>`;

  const blob = new Blob([html], { type: "text/html" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = `osint-report-${ioc.replace(/[^a-zA-Z0-9]/g,"_")}.html`;
  a.click(); URL.revokeObjectURL(url);
}




// -- RAW API RESPONSE TABS -----------------------------------------------------
// One tab per source + one "Full Response" tab
function RawResponseTabs({ sources = {}, raw = {} }) {
  const [activeTab, setActiveTab] = useState("full");

  const sourceTabs = Object.entries(sources).filter(([, v]) => v && typeof v === "object");
  const tabs = [
    { id: "full", label: "Full Response", color: "#6B7280" },
    ...sourceTabs.map(([name]) => ({
      id: name,
      label: name,
      color: SOURCE_COLORS[name] || "#888",
    })),
  ];

  const getContent = (tabId) => {
    if (tabId === "full") return raw;
    return sources[tabId] || {};
  };

  return (
    <div style={{ ...CARD }}>
      {/* Tab bar */}
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 14,
                    borderBottom: "1px solid #1f2937", paddingBottom: 0 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            style={{
              padding: "8px 14px", border: "none", cursor: "pointer",
              fontSize: 11, fontWeight: 700, letterSpacing: "0.05em",
              borderRadius: "6px 6px 0 0", fontFamily: "monospace",
              background: activeTab === t.id ? "#0d1117" : "transparent",
              color: activeTab === t.id ? t.color : "#4B5563",
              borderBottom: activeTab === t.id ? `2px solid ${t.color}` : "2px solid transparent",
              transition: "all .12s",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ position: "relative" }}>
        <CopyButton content={JSON.stringify(getContent(activeTab), null, 2)}/>
        <pre style={{
          fontSize: 11, fontFamily: "monospace", color: "#9CA3AF",
          background: "#0d1117", borderRadius: 10, padding: 16,
          margin: 0, border: "1px solid #1f2937",
          maxHeight: 320, overflowY: "auto", overflowX: "auto",
          lineHeight: 1.6,
        }}>
          {JSON.stringify(getContent(activeTab), null, 2)}
        </pre>
      </div>
    </div>
  );
}

function CopyButton({ content }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(content); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      style={{
        position: "absolute", top: 10, right: 10, zIndex: 2,
        padding: "4px 10px", borderRadius: 6, border: "1px solid #374151",
        background: copied ? "#0d2d1a" : "#1f2937", cursor: "pointer",
        fontSize: 11, color: copied ? "#10B981" : "#9CA3AF", fontWeight: 600,
      }}>
      {copied ? "✓ Copied" : "Copy"}
    </button>
  );
}

// -- INTELLIGENCE FRAMEWORK TABS ----------------------------------------------
// Tabbed section: MITRE ATT&CK | OWASP Top 10 | Tags & Pivots
function IntelFrameworkTabs({ mitre = [], owasp = [], tags = [], pivotLinks = [] }) {
  const [tab, setTab] = useState("mitre");

  const TACTIC_COLORS = {
    "Initial Access":        "#EF4444",
    "Execution":             "#F97316",
    "Persistence":           "#F59E0B",
    "Privilege Escalation":  "#EAB308",
    "Defense Evasion":       "#84CC16",
    "Credential Access":     "#10B981",
    "Discovery":             "#06B6D4",
    "Lateral Movement":      "#3B82F6",
    "Command and Control":   "#8B5CF6",
    "Exfiltration":          "#EC4899",
    "Impact":                "#EF4444",
    "Resource Development":  "#6B7280",
  };

  const OWASP_COLORS = [
    "#EF4444","#F97316","#F59E0B","#EAB308","#84CC16",
    "#10B981","#06B6D4","#3B82F6","#8B5CF6","#EC4899",
  ];

  const tabs = [
    { id: "mitre", label: "MITRE ATT&CK",  count: mitre.length,     color: "#3B82F6" },
    { id: "owasp", label: "OWASP Top 10",  count: owasp.length,     color: "#10B981" },
    { id: "pivot", label: "Tags & Pivots", count: (tags?.length||0) + pivotLinks.length, color: "#F59E0B" },
  ];

  return (
    <div style={{ ...CARD }}>
      {/* Tab bar */}
      <div style={{ display: "flex", gap: 4, marginBottom: 18, borderBottom: "1px solid #1f2937", paddingBottom: 0 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{
              padding: "10px 18px", border: "none", cursor: "pointer", fontSize: 12,
              fontWeight: 800, letterSpacing: "0.06em", borderRadius: "8px 8px 0 0",
              background: tab === t.id ? "#111827" : "transparent",
              color: tab === t.id ? t.color : "#4B5563",
              borderBottom: tab === t.id ? `2px solid ${t.color}` : "2px solid transparent",
              display: "flex", alignItems: "center", gap: 7, transition: "all .15s",
            }}>
            {t.label}
            <span style={{
              padding: "1px 7px", borderRadius: 20, fontSize: 10, fontWeight: 800,
              background: tab === t.id ? t.color + "22" : "#1f2937",
              color: tab === t.id ? t.color : "#4B5563",
              border: tab === t.id ? `1px solid ${t.color}44` : "1px solid #374151",
            }}>{t.count}</span>
          </button>
        ))}
      </div>

      {/* MITRE ATT&CK tab */}
      {tab === "mitre" && (
        <div>
          {mitre.length === 0 ? (
            <div style={{ textAlign: "center", padding: "32px 0", color: "#4B5563", fontSize: 13 }}>
              No MITRE techniques identified for this indicator.
            </div>
          ) : (
            <>
              <div style={{ fontSize: 11, color: "#4B5563", marginBottom: 14 }}>
                Click any technique to view its full details on attack.mitre.org
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
                {mitre.map((m, i) => {
                  const tacticColor = TACTIC_COLORS[m.tactic] || "#6B7280";
                  const isObj = typeof m === "object";
                  const id    = isObj ? (m.id || "") : m;
                  const name  = isObj ? (m.name || m) : m;
                  const tactic = isObj ? (m.tactic || "") : "";
                  const url   = isObj ? (m.url || `https://attack.mitre.org/techniques/${id.replace(".","/")}/`) : `https://attack.mitre.org/search/?query=${encodeURIComponent(name)}`;
                  return (
                    <a key={i} href={url} target="_blank" rel="noreferrer" style={{ textDecoration: "none" }}>
                      <div style={{
                        background: "#0d1117", border: `1px solid ${tacticColor}33`,
                        borderLeft: `3px solid ${tacticColor}`, borderRadius: 10,
                        padding: "12px 14px", cursor: "pointer", transition: "all .15s",
                      }}
                        onMouseEnter={e => { e.currentTarget.style.background = "#111827"; e.currentTarget.style.borderColor = tacticColor; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "#0d1117"; e.currentTarget.style.borderColor = `${tacticColor}33`; }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                          <span style={{ fontSize: 12, fontWeight: 800, color: tacticColor, fontFamily: "monospace" }}>{id}</span>
                          <span style={{ fontSize: 10, color: tacticColor, background: tacticColor + "22", padding: "2px 8px", borderRadius: 20, fontWeight: 700 }}>↗</span>
                        </div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: "#F9FAFB", marginBottom: 4 }}>{name}</div>
                        {tactic && (
                          <div style={{ fontSize: 10, color: "#6B7280", fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                            {tactic}
                          </div>
                        )}
                      </div>
                    </a>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* OWASP Top 10 tab */}
      {tab === "owasp" && (
        <div>
          {owasp.length === 0 ? (
            <div style={{ textAlign: "center", padding: "32px 0", color: "#4B5563", fontSize: 13 }}>
              No OWASP categories mapped for this indicator type.
            </div>
          ) : (
            <>
              <div style={{ fontSize: 11, color: "#4B5563", marginBottom: 14 }}>
                Click any category to view the full OWASP documentation
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {owasp.map((o, i) => {
                  const color = OWASP_COLORS[i % OWASP_COLORS.length];
                  const isObj = typeof o === "object";
                  const id    = isObj ? o.id    : o;
                  const name  = isObj ? o.name  : o;
                  const url   = isObj ? o.url   : `https://owasp.org/Top10/`;
                  return (
                    <a key={i} href={url} target="_blank" rel="noreferrer" style={{ textDecoration: "none" }}>
                      <div style={{
                        display: "flex", alignItems: "center", gap: 14,
                        background: "#0d1117", border: `1px solid ${color}33`,
                        borderRadius: 10, padding: "12px 16px", cursor: "pointer", transition: "all .15s",
                      }}
                        onMouseEnter={e => { e.currentTarget.style.background = "#111827"; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "#0d1117"; }}
                      >
                        <div style={{ width: 48, height: 48, borderRadius: 10, background: color + "22", border: `1px solid ${color}44`, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                          <span style={{ fontSize: 9, fontWeight: 800, color, letterSpacing: "0.04em" }}>OWASP</span>
                          <span style={{ fontSize: 11, fontWeight: 800, color }}>{id?.split(":")[0]}</span>
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 11, color, fontWeight: 800, letterSpacing: "0.06em", marginBottom: 3 }}>{id}</div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: "#F9FAFB" }}>{name}</div>
                        </div>
                        <span style={{ fontSize: 16, color: "#374151" }}>↗</span>
                      </div>
                    </a>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* Tags & Pivots tab */}
      {tab === "pivot" && (
        <div>
          {tags?.length > 0 && (
            <div style={{ marginBottom: 18 }}>
              <div style={{ ...PTITLE }}>THREAT TAGS</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                {tags.map(t => (
                  <span key={t} style={{ background: "#1e3a5f", color: "#93C5FD", border: "1px solid #3B82F633", padding: "5px 14px", borderRadius: 20, fontSize: 12, fontWeight: 700 }}>{t}</span>
                ))}
              </div>
            </div>
          )}
          <div style={{ ...PTITLE }}>PIVOT LINKS</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {pivotLinks.map(([label, href]) => (
              <a key={label} href={href} target="_blank" rel="noreferrer"
                style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 12px", borderRadius: 8, fontSize: 13, color: "#3B82F6", textDecoration: "none", fontWeight: 600, background: "#0d1117", border: "1px solid #1f2937", transition: "all .12s" }}
                onMouseEnter={e => { e.currentTarget.style.background = "#111827"; e.currentTarget.style.borderColor = "#3B82F644"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "#0d1117"; e.currentTarget.style.borderColor = "#1f2937"; }}
              >
                <span>{label}</span>
                <span style={{ fontSize: 12, color: "#374151" }}>↗</span>
              </a>
            ))}
            {pivotLinks.length === 0 && (
              <div style={{ textAlign: "center", padding: "24px 0", color: "#4B5563", fontSize: 13 }}>No pivot links available.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// -- AI ANALYSIS RENDERER -----------------------------------------------------
// Parses Claude's markdown bold headers (**Header**) into styled sections
function AIAnalysisRenderer({ content }) {
  if (!content) return null;

  // Split on **Section Title** pattern
  const parts = content.split(/(\*\*[^*]+\*\*)/g);

  const elements = [];
  let currentSection = null;
  let currentBody   = [];

  const flushSection = () => {
    if (currentSection !== null) {
      elements.push({ header: currentSection, body: currentBody.join("").trim() });
      currentBody   = [];
      currentSection = null;
    }
  };

  parts.forEach((part) => {
    const headerMatch = part.match(/^\*\*([^*]+)\*\*$/);
    if (headerMatch) {
      flushSection();
      currentSection = headerMatch[1];
    } else if (currentSection !== null) {
      currentBody.push(part);
    } else if (part.trim()) {
      elements.push({ header: null, body: part.trim() });
    }
  });
  flushSection();

  const sectionColors = {
    "Executive Summary":    { accent: "#3B82F6", bg: "#0d1b2e" },
    "Source Analysis":      { accent: "#10B981", bg: "#0d2d1a" },
    "Threat Assessment":    { accent: "#F59E0B", bg: "#2d1f0a" },
    "Recommended Actions":  { accent: "#EF4444", bg: "#2d0f0f" },
    "Analyst Notes":        { accent: "#A78BFA", bg: "#1e1535" },
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {elements.map((el, i) => {
        const colors = sectionColors[el.header] || { accent: "#6B7280", bg: "#111827" };
        if (!el.header) {
          return (
            <p key={i} style={{ fontSize: 13, color: "#9CA3AF", lineHeight: 1.7, margin: 0 }}>
              {el.body}
            </p>
          );
        }
        return (
          <div key={i} style={{ background: colors.bg, border: `1px solid ${colors.accent}33`, borderLeft: `3px solid ${colors.accent}`, borderRadius: 10, padding: "14px 16px" }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: colors.accent, letterSpacing: "0.08em", marginBottom: 8, textTransform: "uppercase" }}>
              {el.header}
            </div>
            <div style={{ fontSize: 13, color: "#D1D5DB", lineHeight: 1.75 }}>
              {el.body.split("\n").map((line, j) => {
                const trimmed = line.trim();
                if (!trimmed) return null;
                // Bullet points
                if (trimmed.startsWith("- ") || trimmed.startsWith("• ")) {
                  return (
                    <div key={j} style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                      <span style={{ color: colors.accent, flexShrink: 0, marginTop: 2 }}>▸</span>
                      <span>{trimmed.replace(/^[-•]\s*/, "")}</span>
                    </div>
                  );
                }
                // Numbered points
                const numMatch = trimmed.match(/^(\d+\.?)\s+(.+)/);
                if (numMatch) {
                  return (
                    <div key={j} style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                      <span style={{ color: colors.accent, flexShrink: 0, fontWeight: 700, minWidth: 18 }}>{numMatch[1]}</span>
                      <span>{numMatch[2]}</span>
                    </div>
                  );
                }
                return <p key={j} style={{ margin: "0 0 4px 0" }}>{trimmed}</p>;
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}



// -- REPORT PAGE ---------------------------------------------------------------
function ReportPage({ ioc, iocType, data, onBack }) {
  const d            = mapResponse(data, iocType);
  const summaryLines = buildSummaryLines(ioc, iocType, d);
  const score        = d.score;
  const vs           = verdictStyle(d.verdict);
  const activeType   = IOC_TYPES.find((t) => t.id === iocType);
  const pieData = Object.entries(d.sources).map(([name, src]) => {
    const val = src?.score ?? 0;
    return { label: name, value: val > 0 ? val : 5, color: val > 0 ? (SOURCE_COLORS[name] || "#888") : "#10B981" };
  });
  const pivotLinks   = getPivotLinks(ioc, iocType);
  const seen         = new Set(pivotLinks.map(([l]) => l));
  const allLinks     = [...pivotLinks, ...Object.entries(d.sources).filter(([k, v]) => v?.link && !seen.has(k)).map(([k, v]) => [k, v.link])];
  const [copied, setCopied] = useState(false);
  const handleCopy = () => { copySummary(summaryLines); setCopied(true); setTimeout(() => setCopied(false), 1500); };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0f1a", fontFamily: "system-ui, sans-serif" }}>
      <div style={{ background: "#111827", borderBottom: "1px solid #1f2937", padding: "14px 28px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={onBack} style={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "9px 18px", fontSize: 13, color: "#9CA3AF", cursor: "pointer", fontWeight: 700 }}>← Back</button>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "#F9FAFB" }}>Intelligence Report</div>
            <div style={{ fontSize: 11, color: "#6B7280", fontFamily: "monospace" }}>{ioc}</div>
          </div>
        </div>
        <button onClick={() => downloadReport(ioc, iocType, d, summaryLines)}
          style={{ background: "linear-gradient(135deg,#2563EB,#3B82F6)", color: "white", border: "none", borderRadius: 10, padding: "11px 24px", fontSize: 14, fontWeight: 800, cursor: "pointer", display: "flex", alignItems: "center", gap: 8, boxShadow: "0 0 20px #3B82F655" }}>
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1v8M4 6l3 3 3-3M2 11h10" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
          Download Report
        </button>
      </div>

      <div style={{ padding: "24px 28px", display: "flex", flexDirection: "column", gap: 16, maxWidth: 1200, margin: "0 auto" }}>
        <VerdictBanner verdict={d.verdict} score={score}/>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 12 }}>
          {[
            { label: "RISK SCORE",  value: `${score}/100`,      accent: scoreColor(score) },
            { label: "VERDICT",     value: vs.label,            accent: vs.color          },
            { label: "CONFIDENCE",  value: `${d.confidence}%`,  accent: "#3B82F6"         },
            { label: "IOC TYPE",    value: activeType?.label,   accent: activeType?.color },
          ].map(({ label, value, accent }) => (
            <div key={label} style={{ background: "#111827", border: `1px solid ${accent}33`, borderRadius: 14, padding: "18px 20px", boxShadow: `0 0 16px ${accent}11` }}>
              <div style={{ fontSize: 10, color: "#4B5563", marginBottom: 8, fontWeight: 700, letterSpacing: "0.1em" }}>{label}</div>
              <div style={{ fontSize: 26, fontWeight: 800, color: accent }}>{value}</div>
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
          <div style={{ ...CARD, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ ...PTITLE, width: "100%" }}>RISK GAUGE</div>
            <ScoreGauge score={score} size={200}/>
          </div>
          <div style={{ ...CARD }}>
            <div style={{ ...PTITLE }}>SOURCE DISTRIBUTION</div>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <PieChart data={pieData} size={150} centerLabel={pieData.length} centerSub="SOURCES"/>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1 }}>
                {Object.entries(d.sources).map(([name, src]) => {
                  const s   = src?.score ?? 0;
                  const col = SOURCE_COLORS[name] || "#888";
                  return (
                    <div key={name} style={{ display: "flex", alignItems: "center", gap: 7 }}>
                      <span style={{ width: 9, height: 9, borderRadius: "50%", background: s > 0 ? col : "#10B981", display: "inline-block", flexShrink: 0, boxShadow: `0 0 4px ${s > 0 ? col : "#10B981"}` }}/>
                      <span style={{ fontSize: 11, color: "#6B7280" }}>{name}</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: "#F9FAFB", marginLeft: "auto" }}>{s === 0 ? "Clean" : s}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
          <div style={{ ...CARD, display: "flex", flexDirection: "column" }}>
            <div style={{ ...PTITLE }}>CONFIDENCE</div>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", flex: 1 }}>
              <ConfidenceDonut confidence={d.confidence} size={150}/>
            </div>
          </div>
        </div>

        <div style={{ ...CARD }}>
          <div style={{ ...PTITLE }}>SOURCE SCORES</div>
          <BarChart sources={d.sources}/>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div style={{ ...CARD }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 12, borderBottom: "1px solid #1f2937", marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: "#4B5563", letterSpacing: "0.12em" }}>SUMMARY</div>
              <button onClick={handleCopy} style={{ fontSize: 12, padding: "7px 16px", borderRadius: 8, border: "1px solid #374151", background: copied ? "#0d2d1a" : "#1f2937", cursor: "pointer", color: copied ? "#10B981" : "#9CA3AF", fontWeight: 700 }}>
                {copied ? "✓ Copied" : "Copy"}
              </button>
            </div>
            {summaryLines.map((line, i) => (
              <div key={i} style={{ padding: "8px 0", borderBottom: i < summaryLines.length - 1 ? "1px solid #1f2937" : "none", fontSize: i === 0 ? 14 : 12, fontWeight: i === 0 ? 700 : 400, color: i === 0 ? "#F9FAFB" : "#6B7280", fontFamily: "monospace" }}>
                {line}
              </div>
            ))}
          </div>
          <div style={{ ...CARD }}>
            <div style={{ ...PTITLE }}>INTELLIGENCE SOURCES</div>
            {Object.entries(d.sources).map(([name, src]) => {
              const s   = src?.score ?? 0;
              const b   = sourceBadge(s);
              const col = SOURCE_COLORS[name] || "#888";
              return (
                <div key={name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "11px 0", borderBottom: "1px solid #1f2937" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ width: 10, height: 10, borderRadius: "50%", background: col, flexShrink: 0, display: "inline-block", boxShadow: `0 0 6px ${col}` }}/>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: "#F9FAFB" }}>{name}</div>
                      {src?.link && <a href={src.link} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: "#3B82F6", textDecoration: "none" }}>View →</a>}
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 80, background: "#1f2937", borderRadius: 4, height: 6, overflow: "hidden" }}>
                      <div style={{ height: 6, borderRadius: 4, width: `${Math.max(s,2)}%`, background: col, boxShadow: `0 0 4px ${col}` }}/>
                    </div>
                    <span style={{ fontSize: 12, padding: "3px 10px", borderRadius: 20, background: b.bg, color: b.color, fontWeight: 700, minWidth: 55, textAlign: "center", border: `1px solid ${b.color}33` }}>{s === 0 ? "Clean" : `${s}/100`}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* AI Analysis section - always rendered */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ ...CARD, background: "linear-gradient(135deg, #0d1b2e 0%, #0d1117 100%)", border: "1px solid #3B82F644" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, paddingBottom: 12, borderBottom: "1px solid #3B82F622", marginBottom: 16 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg, #2563EB, #7C3AED)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 800, color: "#F9FAFB", letterSpacing: "0.05em" }}>AI THREAT ANALYSIS</div>
                <div style={{ fontSize: 11, color: "#6B7280" }}>Powered by Claude AI · {new Date().toLocaleString()}</div>
              </div>
              <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
                <div style={{ padding: "3px 10px", borderRadius: 20, background: "#1e3a5f", border: "1px solid #3B82F633", fontSize: 11, color: "#60A5FA", fontWeight: 700 }}>Claude</div>
                {d.ai_analysis && <CopyButton content={d.ai_analysis}/>}
              </div>
            </div>
            {d.ai_analysis ? (
              <AIAnalysisRenderer content={d.ai_analysis}/>
            ) : (
              <div style={{ padding: "20px 0", textAlign: "center" }}>
                <div style={{ fontSize: 13, color: "#4B5563", marginBottom: 8 }}>AI analysis not available.</div>
                <div style={{ fontSize: 11, color: "#374151" }}>Ensure <code style={{ background: "#1f2937", padding: "2px 6px", borderRadius: 4, color: "#60A5FA" }}>ANTHROPIC_API_KEY</code> is set in <code style={{ background: "#1f2937", padding: "2px 6px", borderRadius: 4, color: "#60A5FA" }}>.env</code>.</div>
              </div>
            )}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {d.summary && (
                <div style={{ ...CARD, border: "1px solid #3B82F622" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                    <div style={{ ...PTITLE, margin: 0 }}>ANALYST ASSESSMENT</div>
                    <CopyButton content={d.summary}/>
                  </div>
                  <pre style={{ fontSize: 12, fontFamily: "'JetBrains Mono', 'Fira Code', monospace", color: "#E6EDF3", lineHeight: 1.85, whiteSpace: "pre-wrap", margin: 0, letterSpacing: "0.01em" }}>{d.summary}</pre>
                </div>
              )}
              <InlineIOCChat ioc={d.ioc} iocType={iocType}/>
            </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          {Object.keys(d.geo).length > 0 && (
            <div style={{ ...CARD }}>
              <div style={{ ...PTITLE }}>GEOLOCATION &amp; ENRICHMENT</div>
              {Object.entries(d.geo).map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "9px 0", borderBottom: "1px solid #1f2937" }}>
                  <span style={{ fontSize: 12, color: "#6B7280" }}>{k}</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: "#F9FAFB" }}>{String(v)}</span>
                </div>
              ))}
            </div>
          )}
          <IntelFrameworkTabs mitre={d.mitre} owasp={d.owasp} tags={d.tags} pivotLinks={allLinks}/>
        </div>

        <RawResponseTabs sources={d.sources} raw={d.raw}/>
      </div>
    </div>
  );
}

// -- MAIN APP ------------------------------------------------------------------

// -- THREAT FEED --------------------------------------------------------------
// All AI/Claude calls go through the FastAPI backend - no API keys in frontend

function ThreatFeedCard({ item, onAnalyze }) {
  const sevColor = item.severity === "CRITICAL" ? "#EF4444" : item.severity === "HIGH" ? "#F59E0B" : "#10B981";
  const catColors = {
    Malware: "#A78BFA", Ransomware: "#EF4444", CVE: "#F97316",
    "Zero-Day": "#F43F5E", "Threat Actor": "#3B82F6", Campaign: "#10B981", Vulnerability: "#F59E0B",
  };
  const catColor = catColors[item.category] || "#6B7280";
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      onClick={() => setExpanded(x => !x)}
      style={{ background: "#0d1117", border: `1px solid ${sevColor}22`, borderLeft: `3px solid ${sevColor}`, borderRadius: 12, padding: "16px 18px", cursor: "pointer", transition: "background .15s" }}
      onMouseEnter={e => e.currentTarget.style.background = "#111827"}
      onMouseLeave={e => e.currentTarget.style.background = "#0d1117"}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10, marginBottom: 8 }}>
        <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
          <span style={{ padding: "2px 8px", borderRadius: 20, background: catColor + "22", border: `1px solid ${catColor}44`, fontSize: 10, fontWeight: 800, color: catColor, letterSpacing: "0.06em" }}>{item.category}</span>
          <span style={{ padding: "2px 8px", borderRadius: 20, background: sevColor + "18", border: `1px solid ${sevColor}33`, fontSize: 10, fontWeight: 800, color: sevColor, letterSpacing: "0.06em" }}>{item.severity}</span>
        </div>
        <span style={{ fontSize: 11, color: "#374151", flexShrink: 0 }}>{expanded ? "▲" : "▼"}</span>
      </div>
      <div style={{ fontSize: 14, fontWeight: 700, color: "#F9FAFB", marginBottom: 6, lineHeight: 1.4 }}>{item.title}</div>
      <div style={{ fontSize: 12, color: "#6B7280", lineHeight: 1.6 }}>
        {expanded ? item.summary : item.summary?.slice(0, 110) + (item.summary?.length > 110 ? "…" : "")}
      </div>
      {expanded && (
        <div style={{ marginTop: 12 }}>
          {(() => {
            const analysable = (item.ioc_examples || []).filter(Boolean).map(ioc => {
              const c = cleanIoc(ioc);
              const t = c ? detectType(c) : null;
              return c && t ? { raw: ioc, clean: c, type: t } : null;
            }).filter(Boolean);
            if (!analysable.length) return null;
            const typeColors = { ip:"#3B82F6", domain:"#10B981", url:"#F43F5E", hash:"#F59E0B", email:"#A78BFA" };
            return (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 800, color: "#4B5563", letterSpacing: "0.08em", marginBottom: 6 }}>EXAMPLE IOCs - click to analyse</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {analysable.map(({ clean, type }, i) => (
                    <button key={i} onClick={e => { e.stopPropagation(); onAnalyze(clean); }}
                      style={{ padding: "3px 10px", background: "#1e3a5f", border: `1px solid ${typeColors[type]}44`, borderRadius: 6, fontSize: 11, color: typeColors[type], fontWeight: 600, cursor: "pointer", fontFamily: "monospace", display: "flex", alignItems: "center", gap: 5 }}>
                      <span style={{ fontSize: 9, opacity: 0.7, textTransform: "uppercase" }}>{type}</span>
                      {clean} →
                    </button>
                  ))}
                </div>
              </div>
            );
          })()}
          {item.tags?.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 8 }}>
              {item.tags.map(t => <span key={t} style={{ padding: "2px 8px", background: "#1f2937", borderRadius: 20, fontSize: 10, color: "#6B7280" }}>#{t}</span>)}
            </div>
          )}
          {item.source_url
            ? <a href={item.source_url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()} style={{ display: "inline-flex", alignItems: "center", gap: 4, marginTop: 8, fontSize: 10, color: "#3B82F6", textDecoration: "none" }}>🔗 {item.source} ↗</a>
            : item.source && <div style={{ marginTop: 8, fontSize: 10, color: "#374151" }}>Source: {item.source}</div>
          }
        </div>
      )}
    </div>
  );
}

function HomePageWithFeed({ setView, setIocType, setIoc, setData, onAnalyze,
  FEED_CATS, feedItems, feedLoading, feedErrors, loadCategory }) {
  // Feed state is lifted to MainApp so it persists across navigation
  const feed = Object.values(feedItems).filter(Boolean);

  // Clean and normalise an IOC before analysing
  const cleanIoc = (val) => {
    let v = val.trim().replace(/^['"]+|['"]+$/g, "").trim();
    if (!v || v === "N/A" || v === "n/a" || v === "-") return null;
    if (v.includes(" ") && !v.startsWith("http")) return null;
    if (v.length < 4) return null;
    // ip:port → strip port
    if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(v)) v = v.split(":")[0];
    // CIDR → strip mask
    if (/^\d{1,3}(\.\d{1,3}){3}\/\d+$/.test(v)) v = v.split("/")[0];
    // wildcard domain
    if (v.startsWith("*.")) v = v.slice(2);
    return v;
  };

  const detectType = (val) => {
    const v = (val || "").trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v))             return "ip";
    if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v))        return "email";
    if (/^https?:\/\//.test(v))                          return "url";
    if (/^[a-fA-F0-9]{32}$/.test(v))                    return "hash";
    if (/^[a-fA-F0-9]{40}$/.test(v))                    return "hash";
    if (/^[a-fA-F0-9]{64}$/.test(v))                    return "hash";
    if (/^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}\.[a-zA-Z]{2,}$/.test(v)) return "domain";
    return null;
  };

  const handleAnalyze = (ioc) => {
    const cleaned = cleanIoc(ioc);
    if (!cleaned) return;
    const detectedIocType = detectType(cleaned) || "ip";
    setIocType(detectedIocType);
    setIoc(cleaned);
    setData(null);
    setPendingAnalyze(true);
    setView("analyze");
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0f1a", fontFamily: "system-ui, sans-serif", position: "relative", overflow: "hidden" }}>
      <div style={{ position: "fixed", inset: 0, backgroundImage: "linear-gradient(#1f293712 1px, transparent 1px), linear-gradient(90deg, #1f293712 1px, transparent 1px)", backgroundSize: "44px 44px", pointerEvents: "none", zIndex: 0 }}/>
      <div style={{ position: "fixed", top: "10%", left: "5%", width: 600, height: 600, borderRadius: "50%", background: "radial-gradient(circle, #3B82F608, transparent 70%)", pointerEvents: "none", zIndex: 0 }}/>
      <div style={{ position: "fixed", bottom: "5%", right: "10%", width: 500, height: 500, borderRadius: "50%", background: "radial-gradient(circle, #EF444408, transparent 70%)", pointerEvents: "none", zIndex: 0 }}/>

      <div style={{ position: "relative", zIndex: 1, maxWidth: 1200, margin: "0 auto", padding: "40px 24px" }}>

        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 48 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{ width: 48, height: 48, borderRadius: 14, background: "linear-gradient(135deg, #1e3a5f, #3B82F6)", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 0 24px #3B82F655" }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="white" strokeWidth="1.5"/>
                <circle cx="12" cy="12" r="4"  stroke="white" strokeWidth="1.5"/>
                <line x1="12" y1="2"  x2="12" y2="7"  stroke="white" strokeWidth="1.5"/>
                <line x1="12" y1="17" x2="12" y2="22" stroke="white" strokeWidth="1.5"/>
                <line x1="2"  y1="12" x2="7"  y2="12" stroke="white" strokeWidth="1.5"/>
                <line x1="17" y1="12" x2="22" y2="12" stroke="white" strokeWidth="1.5"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: 20, fontWeight: 900, color: "#F9FAFB", letterSpacing: "-0.02em" }}>OSINT Intelligence</div>
              <div style={{ fontSize: 11, color: "#4B5563", fontWeight: 600, letterSpacing: "0.08em" }}>THREAT ANALYSIS PLATFORM</div>
            </div>
          </div>
          <button onClick={() => setView("analyze")}
            style={{ padding: "10px 24px", background: "linear-gradient(135deg, #2563EB, #3B82F6)", border: "none", borderRadius: 10, fontSize: 13, color: "white", fontWeight: 800, cursor: "pointer", boxShadow: "0 0 16px #3B82F655" }}>
            Open Dashboard →
          </button>
        </div>

        {/* Hero + IOC type buttons */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, marginBottom: 40, alignItems: "center" }}>
          <div>
            <div style={{ background: "#1e3a5f", border: "1px solid #3B82F644", borderRadius: 24, padding: "5px 14px", fontSize: 10, color: "#60A5FA", fontWeight: 800, letterSpacing: "0.1em", marginBottom: 18, display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#10B981", display: "inline-block", boxShadow: "0 0 6px #10B981" }}/>
              LIVE THREAT INTELLIGENCE
            </div>
            <h1 style={{ fontSize: 48, fontWeight: 900, color: "#F9FAFB", marginBottom: 16, lineHeight: 1.05, letterSpacing: "-0.03em" }}>
              Hunt Threats.<br/>
              <span style={{ color: "#3B82F6", textShadow: "0 0 40px #3B82F666" }}>Analyse IOCs.</span>
            </h1>
            <p style={{ fontSize: 14, color: "#6B7280", lineHeight: 1.8, marginBottom: 28, maxWidth: 440 }}>
              Real-time enrichment across VirusTotal, AbuseIPDB, OTX, ThreatFox, MalwareBazaar and more. AI-powered analysis and live threat intelligence.
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {IOC_TYPES.map(t => (
                <button key={t.id}
                  onClick={() => { setIocType(t.id); setIoc(""); setData(null); setView("analyze"); }}
                  style={{ padding: "10px 18px", borderRadius: 24, background: t.bg, border: `1px solid ${t.color}55`, fontSize: 13, color: t.text, fontWeight: 800, cursor: "pointer", transition: "all .12s" }}
                  onMouseEnter={e => e.currentTarget.style.boxShadow = `0 0 20px ${t.color}44`}
                  onMouseLeave={e => e.currentTarget.style.boxShadow = "none"}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[
              { n: "8+",    label: "Intel Sources",   color: "#3B82F6", icon: "🔍" },
              { n: "5",     label: "IOC Types",        color: "#10B981", icon: "🎯" },
              { n: "AI",    label: "Threat Analysis",  color: "#A78BFA", icon: "🤖" },
              { n: "LIVE",  label: "Threat Feed",      color: "#F59E0B", icon: "📡" },
            ].map(({ n, label, color, icon }) => (
              <div key={label} style={{ background: "#111827", border: `1px solid ${color}22`, borderRadius: 14, padding: "20px", textAlign: "center" }}>
                <div style={{ fontSize: 26, marginBottom: 4 }}>{icon}</div>
                <div style={{ fontSize: 26, fontWeight: 900, color, marginBottom: 4, textShadow: `0 0 16px ${color}66` }}>{n}</div>
                <div style={{ fontSize: 10, color: "#4B5563", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase" }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Threat Feed - 6 individual category buttons */}
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 18, overflow: "hidden" }}>
          {/* Header */}
          <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f2937", display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: feed.length > 0 ? "#10B981" : "#374151", boxShadow: feed.length > 0 ? "0 0 8px #10B981" : "none" }}/>
            <div style={{ fontSize: 13, fontWeight: 800, color: "#F9FAFB", letterSpacing: "0.05em", flex: 1 }}>LIVE THREAT INTELLIGENCE FEED</div>
            <div style={{ fontSize: 10, color: "#4B5563" }}>{feed.length}/6 loaded - click a category to fetch</div>
          </div>

          {/* 6 category buttons */}
          <div style={{ padding: "14px 16px", borderBottom: "1px solid #1f2937", display: "flex", flexWrap: "wrap", gap: 8 }}>
            {FEED_CATS.map(cat => {
              const isLoading = feedLoading[cat.id];
              const hasItem   = !!feedItems[cat.id];
              const hasError  = !!feedErrors[cat.id];
              return (
                <button key={cat.id} onClick={() => loadCategory(cat.id)} disabled={isLoading}
                  title={hasError ? feedErrors[cat.id] : hasItem ? "Click to refresh" : "Click to fetch"}
                  style={{
                    padding: "8px 14px", borderRadius: 10, border: `1px solid ${hasError ? "#7f1d1d" : hasItem ? cat.color + "55" : "#374151"}`,
                    background: hasError ? "#2d0f0f" : hasItem ? cat.color + "18" : "#1f2937",
                    color: hasError ? "#F87171" : hasItem ? cat.color : "#6B7280",
                    fontSize: 12, fontWeight: 700, cursor: isLoading ? "default" : "pointer",
                    display: "flex", alignItems: "center", gap: 6, transition: "all .15s",
                  }}
                  onMouseEnter={e => { if (!isLoading) e.currentTarget.style.borderColor = cat.color; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = hasError ? "#7f1d1d" : hasItem ? cat.color + "55" : "#374151"; }}
                >
                  {isLoading
                    ? <><span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>⟳</span> {cat.label}</>
                    : <>{cat.icon} {cat.label}{hasItem ? " ✓" : ""}</>
                  }
                </button>
              );
            })}
          </div>

          {/* Cards grid */}
          <div style={{ padding: 16 }}>
            {feed.length === 0 && (
              <div style={{ textAlign: "center", padding: "32px 20px" }}>
                <div style={{ fontSize: 36, marginBottom: 10 }}>📡</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#F9FAFB", marginBottom: 6 }}>Click any category above to load intelligence</div>
                <div style={{ fontSize: 12, color: "#4B5563" }}>Each button makes one small API call - no rate limit issues.</div>
              </div>
            )}

            {/* Show per-category skeleton while loading */}
            {FEED_CATS.filter(c => feedLoading[c.id]).map(cat => (
              <div key={cat.id} style={{ background: "#0d1117", borderRadius: 12, padding: "16px 18px", border: `1px solid ${cat.color}22`, marginBottom: 10 }}>
                <div style={{ display: "flex", gap: 8, marginBottom: 10, alignItems: "center" }}>
                  <span style={{ fontSize: 16 }}>{cat.icon}</span>
                  <div style={{ width: 80, height: 16, background: "#1f2937", borderRadius: 8, animation: "pulse 1.5s ease-in-out infinite" }}/>
                  <div style={{ width: 50, height: 16, background: "#1f2937", borderRadius: 8, animation: "pulse 1.5s ease-in-out infinite" }}/>
                </div>
                <div style={{ height: 13, background: "#1f2937", borderRadius: 6, marginBottom: 7, width: "80%", animation: "pulse 1.5s ease-in-out infinite" }}/>
                <div style={{ height: 11, background: "#1f2937", borderRadius: 6, width: "60%", animation: "pulse 1.5s ease-in-out infinite" }}/>
              </div>
            ))}

            {feed.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 10 }}>
                {feed.map((item, i) => (
                  <ThreatFeedCard key={item.id || i} item={item} onAnalyze={handleAnalyze}/>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin  { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity:.4 } 50% { opacity:.8 } }
      `}</style>
    </div>
  );
}




// -- INLINE IOC CHAT - replaces Rule-Based Narrative in the report page -------
function InlineIOCChat({ ioc, iocType }) {
  const welcome = `I can see you just analysed **${ioc}** (${(iocType||"").toUpperCase()}).

Ask me anything about it - threat associations, related infrastructure, TTPs, malware family, or recommended response actions.`;
  const [messages, setMessages] = useState([{ role: "assistant", content: welcome }]);
  const [input,    setInput]    = useState("");
  const [loading,  setLoading]  = useState(false);

  const send = async () => {
    const msg = input.trim();
    if (!msg || loading) return;
    setInput("");
    const newMsgs = [...messages, { role: "user", content: msg }];
    setMessages(newMsgs);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/web/chat`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ messages: newMsgs }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setMessages(m => [...m, { role: "assistant", content: data.reply }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", content: `⚠️ Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const renderMsg = (text) =>
    text.split("\n").map((line, i) => {
      if (!line.trim()) return <div key={i} style={{ height: 5 }}/>;
      if (line.startsWith("## ")) return <div key={i} style={{ fontWeight: 800, color: "#3B82F6", fontSize: 13, marginTop: 8, marginBottom: 3 }}>{line.slice(3)}</div>;
      if (line.startsWith("### ")) return <div key={i} style={{ fontWeight: 700, color: "#F9FAFB", fontSize: 12, marginTop: 6, marginBottom: 2 }}>{line.slice(4)}</div>;
      if (line.startsWith("**") && line.endsWith("**")) return <div key={i} style={{ fontWeight: 800, color: "#F9FAFB", fontSize: 12, marginBottom: 2 }}>{line.slice(2,-2)}</div>;
      if (line.match(/^[-•*]\s/)) return (
        <div key={i} style={{ display: "flex", gap: 7, marginBottom: 3, paddingLeft: 4 }}>
          <span style={{ color: "#3B82F6", flexShrink: 0 }}>▸</span>
          <span style={{ fontSize: 12, color: "#D1D5DB", lineHeight: 1.6 }}>{line.replace(/^[-•*]\s/, "")}</span>
        </div>
      );
      return <div key={i} style={{ fontSize: 12, color: "#C9D1D9", lineHeight: 1.65, marginBottom: 2 }}>{line}</div>;
    });

  return (
    <div style={{ ...CARD, display: "flex", flexDirection: "column", height: 420, padding: 0, overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "13px 16px", background: "linear-gradient(135deg, #0d1b2e, #111827)", borderBottom: "1px solid #1f2937", display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        <div style={{ width: 28, height: 28, borderRadius: 7, background: "linear-gradient(135deg, #2563EB, #7C3AED)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 800, color: "#F9FAFB" }}>IOC INTELLIGENCE ASSISTANT</div>
          <div style={{ fontSize: 10, color: "#4B5563" }}>Claude · Live Web Search</div>
        </div>
        <div style={{ marginLeft: "auto", padding: "2px 9px", borderRadius: 20, background: "#1e3a5f", border: "1px solid #3B82F633", fontSize: 10, color: "#60A5FA", fontWeight: 700 }}>Claude</div>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
            <div style={{
              maxWidth: "88%", padding: "9px 13px",
              borderRadius: m.role === "user" ? "14px 14px 4px 14px" : "4px 14px 14px 14px",
              background: m.role === "user" ? "linear-gradient(135deg, #2563EB, #3B82F6)" : "#1f2937",
              border: m.role === "user" ? "none" : "1px solid #374151",
            }}>
              {m.role === "user"
                ? <div style={{ fontSize: 13, color: "white", lineHeight: 1.5 }}>{m.content}</div>
                : <div>{renderMsg(m.content)}</div>
              }
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ display: "flex" }}>
            <div style={{ padding: "9px 13px", background: "#1f2937", borderRadius: "4px 14px 14px 14px", border: "1px solid #374151", display: "flex", gap: 4, alignItems: "center" }}>
              {[0,1,2].map(i => <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: "#3B82F6", animation: `pulse ${0.4+i*0.15}s ease-in-out infinite alternate` }}/>)}
            </div>
          </div>
        )}
        <div ref={el => { if (el) el.scrollIntoView({ behavior: "smooth" }); }}/>
      </div>

      {/* Input */}
      <div style={{ padding: "10px 12px", borderTop: "1px solid #1f2937", display: "flex", gap: 8, flexShrink: 0 }}>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
          placeholder={`Ask anything about ${ioc}…`}
          style={{ flex: 1, padding: "9px 13px", background: "#1f2937", border: "1px solid #374151", borderRadius: 10, fontSize: 13, color: "#F9FAFB", outline: "none", fontFamily: "monospace" }}
        />
        <button onClick={send} disabled={loading || !input.trim()}
          style={{ width: 38, height: 38, borderRadius: 10, background: !input.trim() || loading ? "#1f2937" : "linear-gradient(135deg, #2563EB, #3B82F6)", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M22 2L11 13M22 2L15 22l-4-9-9-4 20-7z" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
        </button>
      </div>
    </div>
  );
}

// -- REPORT CHAT BUTTON - lives only on the full report page ------------------
function ReportChatButton({ ioc, iocType }) {
  const [chatOpen, setChatOpen] = useState(false);
  return (
    <div style={{ position: "fixed", bottom: 24, right: 24, zIndex: 9998 }}>
      {chatOpen && <IOCChat onClose={() => setChatOpen(false)} ioc={ioc} iocType={iocType}/>}
      <button
        onClick={() => setChatOpen(x => !x)}
        title="Ask the IOC Intelligence Assistant"
        style={{
          width: 56, height: 56, borderRadius: "50%",
          background: chatOpen ? "#374151" : "linear-gradient(135deg, #2563EB, #7C3AED)",
          border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: chatOpen ? "0 4px 20px #00000088" : "0 0 0 3px #3B82F622, 0 8px 28px #3B82F666",
          transition: "all .2s",
        }}
        onMouseEnter={e => { if (!chatOpen) e.currentTarget.style.transform = "scale(1.1)"; }}
        onMouseLeave={e => { e.currentTarget.style.transform = "scale(1)"; }}
      >
        {chatOpen
          ? <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M18 6L6 18M6 6l12 12" stroke="white" strokeWidth="2.5" strokeLinecap="round"/></svg>
          : <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
        }
      </button>
      {!chatOpen && (
        <div style={{ position: "absolute", bottom: 64, right: 0, background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "5px 10px", fontSize: 11, color: "#9CA3AF", whiteSpace: "nowrap" }}>
          Ask AI about {ioc}
        </div>
      )}
    </div>
  );
}

// -- IOC CHAT ASSISTANT --------------------------------------------------------
// All requests go to /web/chat on the FastAPI backend - no client-side API keys

function IOCChat({ onClose, ioc = "", iocType = "" }) {
  const welcome = ioc
    ? `I can see you just analysed **${ioc}** (${iocType.toUpperCase()}).\n\nAsk me anything about it - threat associations, related infrastructure, TTPs, malware family, or recommended response actions.`
    : "Hi! Ask me anything about the IOC you analysed - threat intel, malware families, CVEs, or response actions.";
  const [messages, setMessages] = useState([{ role: "assistant", content: welcome }]);
  const [input,   setInput]   = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef              = { current: null };

  const send = async () => {
    const msg = input.trim();
    if (!msg || loading) return;
    setInput("");
    const newMsgs = [...messages, { role: "user", content: msg }];
    setMessages(newMsgs);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/web/chat`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ messages: newMsgs }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setMessages(m => [...m, { role: "assistant", content: data.reply }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", content: `⚠️ Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const renderMsg = (text) =>
    text.split("\n").map((line, i) => {
      if (!line.trim()) return <div key={i} style={{ height: 5 }}/>;
      if (line.startsWith("# "))  return <div key={i} style={{ fontWeight: 900, color: "#F9FAFB", fontSize: 14, marginTop: 10, marginBottom: 4 }}>{line.slice(2)}</div>;
      if (line.startsWith("## ")) return <div key={i} style={{ fontWeight: 800, color: "#3B82F6", fontSize: 13, marginTop: 8, marginBottom: 3 }}>{line.slice(3)}</div>;
      if (line.startsWith("### ")) return <div key={i} style={{ fontWeight: 700, color: "#F9FAFB", fontSize: 12, marginTop: 6, marginBottom: 2 }}>{line.slice(4)}</div>;
      if (line.startsWith("**") && line.endsWith("**")) return <div key={i} style={{ fontWeight: 800, color: "#F9FAFB", fontSize: 12, marginBottom: 2 }}>{line.slice(2,-2)}</div>;
      if (line.match(/^[-•*]\s/)) return (
        <div key={i} style={{ display: "flex", gap: 7, marginBottom: 3, paddingLeft: 4 }}>
          <span style={{ color: "#3B82F6", flexShrink: 0, marginTop: 1 }}>▸</span>
          <span style={{ fontSize: 12, color: "#D1D5DB", lineHeight: 1.6 }}>{line.replace(/^[-•*]\s/, "")}</span>
        </div>
      );
      return <div key={i} style={{ fontSize: 12, color: "#C9D1D9", lineHeight: 1.65, marginBottom: 2 }}>{line}</div>;
    });

  return (
    <div style={{ position: "fixed", bottom: 90, right: 24, width: 420, height: 560, background: "#111827", border: "1px solid #3B82F633", borderRadius: 18, display: "flex", flexDirection: "column", zIndex: 9999, boxShadow: "0 20px 60px #00000088" }}>
      {/* Header */}
      <div style={{ padding: "13px 16px", background: "linear-gradient(135deg,#0d1b2e,#111827)", borderBottom: "1px solid #1f2937", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 30, height: 30, borderRadius: 8, background: "linear-gradient(135deg,#2563EB,#7C3AED)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 800, color: "#F9FAFB" }}>IOC Intelligence Assistant</div>
            <div style={{ fontSize: 10, color: "#4B5563" }}>Claude · Live Web Search</div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "#6B7280", cursor: "pointer", fontSize: 18, padding: "2px 6px", borderRadius: 6 }}>✕</button>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
            <div style={{
              maxWidth: "88%", padding: "10px 13px",
              borderRadius: m.role === "user" ? "14px 14px 4px 14px" : "4px 14px 14px 14px",
              background: m.role === "user" ? "linear-gradient(135deg,#2563EB,#3B82F6)" : "#1f2937",
              border: m.role === "user" ? "none" : "1px solid #374151",
            }}>
              {m.role === "user"
                ? <div style={{ fontSize: 13, color: "white", lineHeight: 1.5 }}>{m.content}</div>
                : <div>{renderMsg(m.content)}</div>
              }
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ display: "flex" }}>
            <div style={{ padding: "10px 14px", background: "#1f2937", borderRadius: "4px 14px 14px 14px", border: "1px solid #374151", display: "flex", gap: 4, alignItems: "center" }}>
              {[0,1,2].map(i => <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: "#3B82F6", animation: `pulse ${0.4+i*0.15}s ease-in-out infinite alternate` }}/>)}
            </div>
          </div>
        )}
        <div ref={el => { if (el) el.scrollIntoView({ behavior: "smooth" }); }}/>
      </div>

      {/* Input */}
      <div style={{ padding: "11px 13px", borderTop: "1px solid #1f2937", display: "flex", gap: 8 }}>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
          placeholder="Ask about any IOC, threat, CVE..."
          style={{ flex: 1, padding: "9px 13px", background: "#1f2937", border: "1px solid #374151", borderRadius: 10, fontSize: 13, color: "#F9FAFB", outline: "none", fontFamily: "monospace" }}
        />
        <button onClick={send} disabled={loading || !input.trim()}
          style={{ width: 38, height: 38, borderRadius: 10, background: !input.trim() || loading ? "#1f2937" : "linear-gradient(135deg,#2563EB,#3B82F6)", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M22 2L11 13M22 2L15 22l-4-9-9-4 20-7z" stroke="white" strokeWidth="2" strokeLinecap="round"/></svg>
        </button>
      </div>


    </div>
  );
}


// -- Auth gate ----------------------------------------------------------------
export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  if (!authed) return <AuthGate onAuth={() => setAuthed(true)} />;
  return <MainApp onLogout={() => { clearToken(); setAuthed(false); }} />;
}

function MainApp({ onLogout }) {
  // -- Feed state - lifted here so it persists when navigating away ----------
  const FEED_CATS = [
    { id: "malware_1", label: "Malware #1",          icon: "🦠", color: "#EF4444" },
    { id: "cve_1",     label: "CVE / Zero-Day",       icon: "🔓", color: "#F97316" },
    { id: "apt_1",     label: "Threat Actor",          icon: "🎯", color: "#3B82F6" },
    { id: "malware_2", label: "Malware #2",            icon: "🐛", color: "#A78BFA" },
    { id: "vuln_1",    label: "Exploited Vuln",        icon: "⚡", color: "#F59E0B" },
    { id: "apt_2",     label: "Breach / Supply Chain", icon: "🔗", color: "#10B981" },
  ];
  const [feedItems,   setFeedItems]   = useState({});
  const [feedLoading, setFeedLoading] = useState({});
  const [feedErrors,  setFeedErrors]  = useState({});

  const loadCategory = async (catId) => {
    setFeedLoading(prev => ({ ...prev, [catId]: true }));
    setFeedErrors(prev => ({ ...prev, [catId]: "" }));
    try {
      const res = await fetch(`${API_BASE}/web/threat-feed/category/${catId}`);
      if (res.status === 429) {
        setFeedErrors(prev => ({ ...prev, [catId]: "Rate limited - wait 30s then retry" }));
        return;
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setFeedItems(prev => ({ ...prev, [catId]: data.item }));
    } catch (e) {
      setFeedErrors(prev => ({ ...prev, [catId]: e.message }));
    } finally {
      setFeedLoading(prev => ({ ...prev, [catId]: false }));
    }
  };
  // -------------------------------------------------------------------------

  const [view,            setView]           = useState("home");
  const [iocType,         setIocType]        = useState("ip");
  const [ioc,             setIoc]            = useState("");
  const [data,            setData]           = useState(null);
  const [detectedType,    setDetectedType]   = useState("ip");  // synced with data
  const [loading,         setLoading]        = useState(false);
  const [copied,          setCopied]         = useState(false);
  const [validationError, setValidationError] = useState(null);
  const [pendingAnalyze,  setPendingAnalyze]  = useState(false);

  const analyze = async () => {
    const trimmed = ioc.trim();
    if (!trimmed) { setValidationError("Please enter a value to analyse."); return; }
    const err = validateIOC(trimmed, iocType);
    if (err) { setValidationError(err); return; }
    setValidationError(null);
    const detected = detectIOC(trimmed);
    setIocType(detected);
    setDetectedType(detected);  // store in sync with data
    setLoading(true);
    setData(null);
    try {
      const res = await axios.get(`${API_BASE}/ioc/analyze`, { params: { value: trimmed }, headers: authHeaders() });
      setData(res.data);
      setDetectedType(detected);  // set again after data arrives - guaranteed sync
    } catch (err2) {
      console.error(err2);
      setValidationError("Analysis failed - check the API is running.");
    }
    setLoading(false);
  };

  const d            = data ? mapResponse(data, detectedType) : null;
  const activeType   = IOC_TYPES.find((t) => t.id === detectedType);
  const summaryLines = d ? buildSummaryLines(ioc, detectedType, d) : [];
  const handleCopy   = () => { copySummary(summaryLines); setCopied(true); setTimeout(() => setCopied(false), 1500); };

  const dashLinks = d ? (() => {
    const links = getPivotLinks(ioc, detectedType);
    const seen  = new Set(links.map(([l]) => l));
    return [...links, ...Object.entries(d.sources).filter(([k, v]) => v?.link && !seen.has(k)).map(([k, v]) => [k, v.link])];
  })() : [];

  if (view === "report" && d) return <ReportPage ioc={ioc} iocType={detectedType} data={data} onBack={() => setView("analyze")}/>;
  // -- SIEM PAGE -------------------------------------------------------------
  if (view === "siem") return <SiemKeysPage onBack={() => setView("home")} />;

  // -- HOME PAGE --------------------------------------------------------------
  if (view === "home") return (
    <HomePageWithFeed
      setView={setView}
      setIocType={setIocType}
      setIoc={setIoc}
      setData={setData}
      onAnalyze={analyze}
      FEED_CATS={FEED_CATS}
      feedItems={feedItems}
      feedLoading={feedLoading}
      feedErrors={feedErrors}
      loadCategory={loadCategory}
    />
  );

  // -- DASHBOARD VIEW ---------------------------------------------------------
  return (
    <div style={{ minHeight: "100vh", background: "#0a0f1a", fontFamily: "system-ui, sans-serif" }}>
      {/* Topbar */}
      <div style={{ background: "#111827", borderBottom: "1px solid #1f2937", padding: "13px 24px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: "linear-gradient(135deg, #1e3a5f, #3B82F6)", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 0 12px #3B82F644" }}>
            <svg width="19" height="19" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" stroke="white" strokeWidth="1"/><circle cx="8" cy="8" r="2.5" stroke="white" strokeWidth="1"/></svg>
          </div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 800, color: "#F9FAFB" }}>OSINT SOC Dashboard</div>
            <div style={{ fontSize: 11, color: "#4B5563" }}>Threat Analysis &amp; IOC Enrichment</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#10B981", display: "inline-block", boxShadow: "0 0 8px #10B981" }}/>
            <span style={{ fontSize: 12, color: "#6B7280" }}>All feeds operational</span>
          </span>
          {d && (
            <button onClick={() => setView("report")}
              style={{ background: "linear-gradient(135deg,#2563EB,#3B82F6)", color: "white", border: "none", borderRadius: 8, padding: "10px 20px", fontSize: 13, fontWeight: 800, cursor: "pointer", boxShadow: "0 0 16px #3B82F655" }}>
              Full Report
            </button>
          )}
          <button onClick={() => setView("home")}
            style={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "9px 18px", fontSize: 13, color: "#9CA3AF", cursor: "pointer", fontWeight: 700 }}>
            Home
          </button>
          <button onClick={() => setView("siem")}
            style={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "9px 18px", fontSize: 13, color: "#9CA3AF", cursor: "pointer", fontWeight: 700 }}>
            🔌 SIEM API
          </button>
          
          <button onClick={onLogout}
            style={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "9px 18px", fontSize: 13, color: "#EF4444", cursor: "pointer", fontWeight: 700 }}>
            Log Out
          </button>
        </div>
      </div>

      <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 16 }}>
        {/* Auto-analyze when navigating from threat feed */}
        {pendingAnalyze && ioc && (() => {
          setPendingAnalyze(false);
          setTimeout(() => analyze(), 10);
          return null;
        })()}
      {/* Search */}
        <div style={{ ...CARD }}>
          <div style={{ fontSize: 10, fontWeight: 800, color: "#4B5563", letterSpacing: "0.12em", marginBottom: 14, textTransform: "uppercase" }}>Select IOC Type</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 18 }}>
            {IOC_TYPES.map(t => (
              <button key={t.id}
                onClick={() => { setIocType(t.id); setIoc(""); setData(null); setValidationError(null); }}
                style={{ padding: "11px 22px", borderRadius: 28, cursor: "pointer", border: iocType === t.id ? `1px solid ${t.color}` : "1px solid #374151", background: iocType === t.id ? t.bg : "#1f2937", color: iocType === t.id ? t.text : "#6B7280", fontSize: 14, fontWeight: 800, display: "flex", alignItems: "center", gap: 8, transition: "all .12s", boxShadow: iocType === t.id ? `0 0 16px ${t.color}44` : "none" }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", background: t.color, display: "inline-block", boxShadow: `0 0 5px ${t.color}` }}/>{t.label}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <input value={ioc} onChange={e => { setIoc(e.target.value); if (validationError) setValidationError(null); }} onKeyDown={e => e.key === "Enter" && analyze()} placeholder={PLACEHOLDERS[iocType]}
              style={{ flex: 1, padding: "16px 20px", border: "1px solid #374151", borderRadius: 12, fontSize: 15, background: "#1f2937", color: "#F9FAFB", outline: "none", fontFamily: "monospace" }}
            />
            <button onClick={analyze} disabled={loading}
              style={{ padding: "16px 36px", background: loading ? "#374151" : "linear-gradient(135deg, #2563EB, #3B82F6)", color: "white", border: "none", borderRadius: 12, fontSize: 16, fontWeight: 900, cursor: loading ? "default" : "pointer", whiteSpace: "nowrap", boxShadow: loading ? "none" : "0 0 24px #3B82F666", letterSpacing: "0.02em", transition: "all .12s" }}>
              {loading ? "Analysing..." : "Analyse IOC →"}
            </button>
          </div>
          {validationError && (
            <div style={{ marginTop: 10, padding: "10px 16px", background: "#2d0f0f", border: "1px solid #7f1d1d", borderRadius: 10, display: "flex", alignItems: "center", gap: 10 }}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="#EF4444" strokeWidth="1.5"/><path d="M8 4.5v4M8 10.5h.01" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round"/></svg>
              <span style={{ fontSize: 13, color: "#F87171", fontWeight: 600 }}>{validationError}</span>
            </div>
          )}
          {loading && (
            <div style={{ height: 3, background: "#1f2937", borderRadius: 2, overflow: "hidden", marginTop: 14 }}>
              <div style={{ height: 3, background: "#3B82F6", borderRadius: 2, animation: "loadbar 1.4s ease-in-out infinite", width: "40%", boxShadow: "0 0 10px #3B82F6" }}/>
            </div>
          )}
        </div>

        {d && (
          <>
            <VerdictBanner verdict={d.verdict} score={d.score}/>

            {/* Summary */}
            <div style={{ ...CARD, background: "#0d1b2e", border: "1px solid #3B82F633" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div style={{ fontSize: 10, fontWeight: 800, color: "#3B82F6", letterSpacing: "0.12em", textTransform: "uppercase" }}>Summary</div>
                <button onClick={handleCopy}
                  style={{ fontSize: 12, padding: "8px 18px", borderRadius: 8, border: "1px solid #3B82F633", background: copied ? "#0d2d1a" : "#1e3a5f", cursor: "pointer", color: copied ? "#10B981" : "#60A5FA", fontWeight: 800 }}>
                  {copied ? "✓ Copied" : "Copy"}
                </button>
              </div>
              {summaryLines.map((line, i) => (
                <div key={i} style={{ padding: "6px 0", borderBottom: i < summaryLines.length - 1 ? "1px solid #1e3a5f" : "none", fontSize: i === 0 ? 14 : 12, fontWeight: i === 0 ? 800 : 400, color: i === 0 ? "#F9FAFB" : "#60A5FA", fontFamily: "monospace" }}>
                  {line}
                </div>
              ))}
            </div>

            {/* Charts */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
              <div style={{ ...CARD, display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{ ...PTITLE, width: "100%" }}>RISK GAUGE</div>
                <ScoreGauge score={d.score} size={200}/>
              </div>
              <div style={{ ...CARD }}>
                <div style={{ ...PTITLE }}>SOURCE DISTRIBUTION</div>
                <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                  <PieChart
                    data={Object.entries(d.sources).map(([name, src]) => {
                      const val = src?.score ?? 0;
                      return { label: name, value: val > 0 ? val : 5, color: val > 0 ? (SOURCE_COLORS[name] || "#888") : "#10B981" };
                    })}
                    size={150}
                    centerLabel={Object.keys(d.sources).length}
                    centerSub="SOURCES"
                  />
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {Object.entries(d.sources).map(([name, src]) => {
                      const s   = src?.score ?? 0;
                      const col = SOURCE_COLORS[name] || "#888";
                      return (
                        <div key={name} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ width: 9, height: 9, borderRadius: "50%", background: s > 0 ? col : "#10B981", display: "inline-block", boxShadow: `0 0 5px ${s > 0 ? col : "#10B981"}` }}/>
                          <span style={{ fontSize: 11, color: "#6B7280" }}>{name}</span>
                          <span style={{ fontSize: 12, fontWeight: 700, color: "#F9FAFB", marginLeft: "auto" }}>{s === 0 ? "Clean" : s}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
              <div style={{ ...CARD, display: "flex", flexDirection: "column" }}>
                <div style={{ ...PTITLE }}>CONFIDENCE</div>
                <div style={{ display: "flex", justifyContent: "center", alignItems: "center", flex: 1 }}>
                  <ConfidenceDonut confidence={d.confidence} size={150}/>
                </div>
              </div>
            </div>

            {/* Source scores */}
            <div style={{ ...CARD }}>
              <div style={{ ...PTITLE }}>SOURCE SCORES</div>
              <BarChart sources={d.sources} compact={true}/>
            </div>

            {/* Bottom panels */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 14 }}>
              <div style={{ ...CARD }}>
                <div style={{ ...PTITLE }}>VERDICT &amp; SCORING</div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                  <span style={{ padding: "8px 20px", borderRadius: 28, fontSize: 14, fontWeight: 900, background: verdictStyle(d.verdict).bg, color: verdictStyle(d.verdict).color, border: `1px solid ${verdictStyle(d.verdict).border}`, boxShadow: `0 0 14px ${verdictStyle(d.verdict).accent}44` }}>
                    {verdictStyle(d.verdict).label}
                  </span>
                  <span style={{ fontSize: 34, fontWeight: 900, color: scoreColor(d.score), textShadow: `0 0 16px ${scoreColor(d.score)}88` }}>
                    {d.score}<span style={{ fontSize: 14, color: "#4B5563" }}>/100</span>
                  </span>
                </div>
                <div style={{ background: "#1f2937", borderRadius: 6, height: 12, overflow: "hidden", marginBottom: 8 }}>
                  <div style={{ height: 12, borderRadius: 6, width: `${d.score}%`, background: scoreColor(d.score), boxShadow: `0 0 10px ${scoreColor(d.score)}` }}/>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 16 }}>
                  <span style={{ color: "#10B981", fontWeight: 700 }}>Benign</span>
                  <span style={{ color: "#F59E0B", fontWeight: 700 }}>Suspicious</span>
                  <span style={{ color: "#EF4444", fontWeight: 700 }}>Malicious</span>
                </div>
                {[["Type", activeType?.label], ["Confidence", `${d.confidence}%`]].map(([l, v]) => (
                  <div key={l} style={{ display: "flex", justifyContent: "space-between", padding: "9px 0", borderBottom: "1px solid #1f2937" }}>
                    <span style={{ fontSize: 12, color: "#6B7280" }}>{l}</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "#F9FAFB" }}>{v}</span>
                  </div>
                ))}
                <button onClick={() => setView("report")}
                  style={{ marginTop: 16, width: "100%", padding: "13px", background: "linear-gradient(135deg, #1e3a5f, #2563EB)", color: "#60A5FA", border: "1px solid #3B82F633", borderRadius: 10, fontSize: 14, fontWeight: 800, cursor: "pointer", boxShadow: "0 0 14px #3B82F633" }}>
                  View Full Report →
                </button>
              </div>

              <div style={{ ...CARD }}>
                <div style={{ ...PTITLE }}>INTELLIGENCE SOURCES</div>
                {Object.entries(d.sources).map(([name, src]) => {
                  const s   = src?.score ?? 0;
                  const b   = sourceBadge(s);
                  const col = SOURCE_COLORS[name] || "#888";
                  return (
                    <div key={name} style={{ padding: "10px 12px", border: "1px solid #1f2937", borderRadius: 10, marginBottom: 8, display: "flex", alignItems: "center", justifyContent: "space-between", background: "#0d1117" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                        <span style={{ width: 10, height: 10, borderRadius: "50%", background: col, display: "inline-block", boxShadow: `0 0 7px ${col}` }}/>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: "#F9FAFB" }}>{name}</div>
                          {src?.link && <a href={src.link} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: "#3B82F6", textDecoration: "none" }}>View →</a>}
                        </div>
                      </div>
                      <span style={{ fontSize: 12, padding: "4px 12px", borderRadius: 20, background: b.bg, color: b.color, fontWeight: 800, border: `1px solid ${b.color}33` }}>{s === 0 ? "Clean" : `${s}/100`}</span>
                    </div>
                  );
                })}
              </div>

              <div style={{ ...CARD }}>
                <div style={{ ...PTITLE }}>ENRICHMENT &amp; PIVOT</div>
                {d.geo && Object.entries(d.geo).slice(0, 5).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #1f2937" }}>
                    <span style={{ fontSize: 12, color: "#6B7280" }}>{k}</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "#F9FAFB" }}>{String(v)}</span>
                  </div>
                ))}
                <div style={{ marginTop: 14 }}>
                  {dashLinks.slice(0, 6).map(([label, url]) => (
                    <a key={label} href={url} target="_blank" rel="noreferrer"
                      style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: "#3B82F6", padding: "8px 0", borderBottom: "1px solid #1f2937", textDecoration: "none", fontWeight: 600 }}>
                      {label}<span style={{ color: "#374151", fontSize: 11 }}>→</span>
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {!d && !loading && (
          <div style={{ ...CARD, textAlign: "center", padding: "70px 24px" }}>
            <div style={{ width: 68, height: 68, borderRadius: "50%", background: "#1f2937", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 18px", border: "1px solid #374151" }}>
              <svg width="30" height="30" viewBox="0 0 22 22" fill="none">
                <circle cx="11" cy="11" r="10" stroke="#374151" strokeWidth="1.5"/>
                <circle cx="11" cy="11" r="4"  stroke="#374151" strokeWidth="1.5"/>
              </svg>
            </div>
            <div style={{ fontSize: 18, fontWeight: 800, color: "#F9FAFB", marginBottom: 8 }}>No IOC analysed yet</div>
            <div style={{ fontSize: 14, color: "#4B5563" }}>Select an IOC type above, enter a value, and click Analyse IOC</div>
          </div>
        )}
      </div>
      <style>{`@keyframes loadbar{0%{transform:translateX(-100%)}100%{transform:translateX(350%)}}`}</style>


    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH GATE - Register / Login / Verify / Forgot Password / Reset Password
// ═══════════════════════════════════════════════════════════════════════════════

function PasswordStrengthBar({ password }) {
  if (!password) return null;

  const score = (() => {
    let s = 0;
    if (password.length >= 12) s++;
    if (password.length >= 16) s++;
    if (/[A-Z]/.test(password)) s += 0.5;
    if (/[a-z]/.test(password)) s += 0.5;
    if (/\d/.test(password))    s += 0.5;
    if (/[!@#$%^&*()\-_+=\[\]{}|;:,.<>?]/.test(password)) s += 0.5;
    return Math.min(4, Math.floor(s));
  })();

  const labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
  const colors = ["#EF4444", "#F97316", "#F59E0B", "#10B981", "#10B981"];
  const issues = [];
  if (password.length < 12)                    issues.push("12+ characters");
  if (!/[A-Z]/.test(password))                 issues.push("uppercase letter");
  if (!/[a-z]/.test(password))                 issues.push("lowercase letter");
  if (!/\d/.test(password))                    issues.push("number");
  if (!/[!@#$%^&*()\-_+=\[\]{}|;:,.<>?]/.test(password)) issues.push("special char (!@#$...)");

  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 4 }}>
        {[0,1,2,3].map(i => (
          <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i < score ? colors[score] : "#1f2937", transition: "background .3s" }}/>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: colors[score], fontWeight: 700 }}>{labels[score]}</span>
        {issues.length > 0 && <span style={{ fontSize: 10, color: "#4B5563" }}>Missing: {issues.slice(0,2).join(", ")}</span>}
      </div>
    </div>
  );
}

function AuthCard({ title, subtitle, children }) {
  return (
    <div style={{ minHeight: "100vh", background: "#0a0f1a", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px", fontFamily: "system-ui, sans-serif" }}>
      <div style={{ position: "fixed", inset: 0, backgroundImage: "linear-gradient(#1f293712 1px, transparent 1px), linear-gradient(90deg, #1f293712 1px, transparent 1px)", backgroundSize: "44px 44px", pointerEvents: "none" }}/>
      <div style={{ position: "fixed", top: "15%", left: "10%", width: 500, height: 500, borderRadius: "50%", background: "radial-gradient(circle, #3B82F60a, transparent 70%)", pointerEvents: "none" }}/>
      <div style={{ position: "relative", width: "100%", maxWidth: 420 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ width: 56, height: 56, borderRadius: 16, background: "linear-gradient(135deg, #1e3a5f, #3B82F6)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px", boxShadow: "0 0 32px #3B82F655" }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="white" strokeWidth="1.5"/>
              <circle cx="12" cy="12" r="4"  stroke="white" strokeWidth="1.5"/>
              <line x1="12" y1="2"  x2="12" y2="7"  stroke="white" strokeWidth="1.5"/>
              <line x1="12" y1="17" x2="12" y2="22" stroke="white" strokeWidth="1.5"/>
              <line x1="2"  y1="12" x2="7"  y2="12" stroke="white" strokeWidth="1.5"/>
              <line x1="17" y1="12" x2="22" y2="12" stroke="white" strokeWidth="1.5"/>
            </svg>
          </div>
          <div style={{ fontSize: 10, fontWeight: 800, color: "#3B82F6", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>OSINT Intelligence Platform</div>
          <h1 style={{ fontSize: 24, fontWeight: 900, color: "#F9FAFB", margin: 0 }}>{title}</h1>
          {subtitle && <p style={{ fontSize: 13, color: "#6B7280", margin: "8px 0 0" }}>{subtitle}</p>}
        </div>
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 18, padding: "32px" }}>
          {children}
        </div>
      </div>
    </div>
  );
}

function AuthInput({ label, type = "text", value, onChange, placeholder, autoFocus }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: "block", fontSize: 12, fontWeight: 700, color: "#9CA3AF", marginBottom: 6, letterSpacing: "0.04em" }}>{label}</label>
      <input
        type={type} value={value} onChange={onChange} placeholder={placeholder} autoFocus={autoFocus}
        style={{ width: "100%", padding: "12px 14px", background: "#1f2937", border: "1px solid #374151", borderRadius: 10, fontSize: 14, color: "#F9FAFB", outline: "none", boxSizing: "border-box", fontFamily: "system-ui, sans-serif" }}
        onFocus={e => e.target.style.borderColor = "#3B82F6"}
        onBlur={e  => e.target.style.borderColor = "#374151"}
      />
    </div>
  );
}

function AuthBtn({ children, onClick, loading, disabled, variant = "primary" }) {
  const bg = variant === "primary"
    ? (disabled || loading ? "#1f2937" : "linear-gradient(135deg, #2563EB, #3B82F6)")
    : "#1f2937";
  return (
    <button onClick={onClick} disabled={disabled || loading}
      style={{ width: "100%", padding: "13px", background: bg, border: variant === "secondary" ? "1px solid #374151" : "none", borderRadius: 10, fontSize: 14, color: disabled || loading ? "#4B5563" : "white", fontWeight: 800, cursor: disabled || loading ? "default" : "pointer", boxShadow: !disabled && !loading && variant === "primary" ? "0 0 20px #3B82F644" : "none", transition: "all .15s" }}>
      {loading ? "Please wait…" : children}
    </button>
  );
}

function AuthError({ msg }) {
  if (!msg) return null;
  return <div style={{ padding: "10px 14px", background: "#2d0f0f", border: "1px solid #7f1d1d", borderRadius: 8, fontSize: 13, color: "#F87171", marginBottom: 16 }}>{msg}</div>;
}

function AuthSuccess({ msg }) {
  if (!msg) return null;
  return <div style={{ padding: "10px 14px", background: "#0a2e1a", border: "1px solid #065f26", borderRadius: 8, fontSize: 13, color: "#34d399", marginBottom: 16 }}>{msg}</div>;
}

// -- Register Screen -----------------------------------------------------------
function RegisterScreen({ onSwitch }) {
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [done,     setDone]     = useState(false);

  const submit = async () => {
    setError("");
    if (!email || !password) return setError("Please fill in all fields.");
    if (password !== confirm) return setError("Passwords do not match.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const d = await r.json();
      if (!r.ok) {
        const msg = d.detail?.message || d.detail || "Registration failed";
        const issues = d.detail?.issues || [];
        setError(issues.length ? `${msg}: ${issues.join(", ")}` : msg);
      } else {
        setDone(true);
      }
    } catch { setError("Network error - is the server running?"); }
    finally   { setLoading(false); }
  };

  if (done) return (
    <AuthCard title="Check Your Email" subtitle="A 6-digit code has been sent to your inbox">
      <AuthSuccess msg={`Verification code sent to ${email}`}/>
      <p style={{ fontSize: 13, color: "#6B7280", marginBottom: 20, lineHeight: 1.7 }}>Enter the code to activate your account. Check your spam folder if you don't see it within a minute.</p>
      <AuthBtn onClick={() => onSwitch("verify", email)}>Enter Verification Code →</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 16 }}>
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 13, cursor: "pointer" }}>Back to Login</button>
      </div>
    </AuthCard>
  );

  return (
    <AuthCard title="Create Account" subtitle="Join the OSINT Intelligence Platform">
      <AuthError msg={error}/>
      <AuthInput label="Email Address" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@company.com" autoFocus/>
      <div style={{ marginBottom: 16 }}>
        <label style={{ display: "block", fontSize: 12, fontWeight: 700, color: "#9CA3AF", marginBottom: 6, letterSpacing: "0.04em" }}>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Min. 12 characters"
          style={{ width: "100%", padding: "12px 14px", background: "#1f2937", border: "1px solid #374151", borderRadius: 10, fontSize: 14, color: "#F9FAFB", outline: "none", boxSizing: "border-box" }}
          onFocus={e => e.target.style.borderColor = "#3B82F6"}
          onBlur={e  => e.target.style.borderColor = "#374151"}
        />
        <PasswordStrengthBar password={password}/>
      </div>
      <AuthInput label="Confirm Password" type="password" value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="Re-enter password"/>
      <div style={{ marginBottom: 20, padding: "10px 12px", background: "#0d1117", borderRadius: 8, fontSize: 11, color: "#4B5563", lineHeight: 1.8 }}>
        Password must: be 12+ characters · include uppercase &amp; lowercase · include a number · include a special character
      </div>
      <AuthBtn onClick={submit} loading={loading} disabled={!email || !password || !confirm}>Create Account</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 16 }}>
        <span style={{ fontSize: 13, color: "#4B5563" }}>Already have an account? </span>
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#3B82F6", fontSize: 13, cursor: "pointer", fontWeight: 700 }}>Sign In</button>
      </div>
    </AuthCard>
  );
}

// -- Verify Email Screen -------------------------------------------------------
function VerifyEmailScreen({ initialEmail, onSwitch }) {
  const [email, setEmail] = useState(initialEmail || "");
  const [code,  setCode]  = useState("");
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");
  const [success, setSuccess] = useState("");

  const submit = async () => {
    setError(""); setSuccess("");
    if (!email || !code) return setError("Please enter your email and the 6-digit code.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/verify-email`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const d = await r.json();
      if (!r.ok) setError(d.detail || "Verification failed");
      else { setSuccess(d.message); setTimeout(() => onSwitch("login"), 1500); }
    } catch { setError("Network error"); }
    finally   { setLoading(false); }
  };

  const resend = async () => {
    if (!email) return setError("Enter your email first");
    setLoading(true);
    try {
      await fetch(`${API_BASE}/auth/resend-verification`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      setSuccess("New code sent - check your email");
    } catch { setError("Network error"); }
    finally   { setLoading(false); }
  };

  return (
    <AuthCard title="Verify Your Email" subtitle="Enter the 6-digit code we sent you">
      <AuthError msg={error}/><AuthSuccess msg={success}/>
      <AuthInput label="Email Address" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@company.com"/>
      <AuthInput label="Verification Code" value={code} onChange={e => setCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="123456" autoFocus/>
      <AuthBtn onClick={submit} loading={loading} disabled={code.length !== 6}>Verify Email</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 12 }}>
        <button onClick={resend} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 12, cursor: "pointer" }}>Resend code</button>
        <span style={{ color: "#374151", margin: "0 8px" }}>·</span>
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 12, cursor: "pointer" }}>Back to Login</button>
      </div>
    </AuthCard>
  );
}

// -- Login Screen --------------------------------------------------------------
function LoginScreen({ onSwitch, onMFA }) {
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  const submit = async () => {
    setError("");
    if (!email || !password) return setError("Please enter your email and password.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const d = await r.json();
      if (!r.ok) setError(d.detail || "Login failed");
      else onMFA(email);
    } catch { setError("Network error - is the server running?"); }
    finally   { setLoading(false); }
  };

  return (
    <AuthCard title="Welcome Back" subtitle="Sign in to your analyst account">
      <AuthError msg={error}/>
      <AuthInput label="Email Address" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@company.com" autoFocus/>
      <AuthInput label="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Your password"/>
      <div style={{ textAlign: "right", marginBottom: 20, marginTop: -8 }}>
        <button onClick={() => onSwitch("forgot")} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 12, cursor: "pointer" }}>Forgot password?</button>
      </div>
      <AuthBtn onClick={submit} loading={loading} disabled={!email || !password}>Sign In</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 16 }}>
        <span style={{ fontSize: 13, color: "#4B5563" }}>No account? </span>
        <button onClick={() => onSwitch("register")} style={{ background: "none", border: "none", color: "#3B82F6", fontSize: 13, cursor: "pointer", fontWeight: 700 }}>Create one</button>
      </div>
    </AuthCard>
  );
}

// -- MFA Screen ----------------------------------------------------------------
function MFAScreen({ email, onAuth, onSwitch }) {
  const [code,    setCode]    = useState("");
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  const submit = async () => {
    setError("");
    if (code.length !== 6) return setError("Enter the 6-digit code from your email.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/verify-mfa`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const d = await r.json();
      if (!r.ok) setError(d.detail || "Invalid code");
      else { setToken(d.access_token); onAuth(); }
    } catch { setError("Network error"); }
    finally   { setLoading(false); }
  };

  return (
    <AuthCard title="Two-Factor Verification" subtitle={`Code sent to ${email}`}>
      <AuthError msg={error}/>
      <p style={{ fontSize: 13, color: "#6B7280", marginBottom: 20, lineHeight: 1.7 }}>
        A 6-digit security code has been sent to your email. Enter it below to complete sign-in.
      </p>
      <AuthInput label="Security Code" value={code} onChange={e => setCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="123456" autoFocus/>
      <AuthBtn onClick={submit} loading={loading} disabled={code.length !== 6}>Verify & Sign In</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 12 }}>
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 12, cursor: "pointer" }}>← Back to Login</button>
      </div>
    </AuthCard>
  );
}

// -- Forgot Password Screen ----------------------------------------------------
function ForgotPasswordScreen({ onSwitch }) {
  const [email,   setEmail]   = useState("");
  const [loading, setLoading] = useState(false);
  const [sent,    setSent]    = useState(false);
  const [error,   setError]   = useState("");

  const submit = async () => {
    setError("");
    if (!email) return setError("Please enter your email.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const d = await r.json();
      if (!r.ok) setError(d.detail || "Error");
      else setSent(true);
    } catch { setError("Network error"); }
    finally   { setLoading(false); }
  };

  if (sent) return (
    <AuthCard title="Check Your Email" subtitle="Password reset link sent">
      <AuthSuccess msg="If that email is registered, a reset link has been sent."/>
      <p style={{ fontSize: 13, color: "#6B7280", marginBottom: 20, lineHeight: 1.7 }}>
        Click the link in the email to reset your password. The link expires in 1 hour.
      </p>
      <AuthBtn onClick={() => onSwitch("login")} variant="secondary">← Back to Login</AuthBtn>
    </AuthCard>
  );

  return (
    <AuthCard title="Reset Password" subtitle="We'll send a reset link to your email">
      <AuthError msg={error}/>
      <AuthInput label="Email Address" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@company.com" autoFocus/>
      <AuthBtn onClick={submit} loading={loading} disabled={!email}>Send Reset Link</AuthBtn>
      <div style={{ textAlign: "center", marginTop: 12 }}>
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#4B5563", fontSize: 13, cursor: "pointer" }}>← Back to Login</button>
      </div>
    </AuthCard>
  );
}

// -- Reset Password Screen (reached from email link) ---------------------------
function ResetPasswordScreen({ token, onSwitch }) {
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [done,     setDone]     = useState(false);

  const submit = async () => {
    setError("");
    if (!password || !confirm) return setError("Please fill in both fields.");
    if (password !== confirm)  return setError("Passwords do not match.");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/auth/reset-password`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      const d = await r.json();
      if (!r.ok) {
        const msg = d.detail?.message || d.detail || "Reset failed";
        const issues = d.detail?.issues || [];
        setError(issues.length ? `${msg}: ${issues.join(", ")}` : msg);
      } else setDone(true);
    } catch { setError("Network error"); }
    finally   { setLoading(false); }
  };

  if (done) return (
    <AuthCard title="Password Updated" subtitle="Your password has been changed">
      <AuthSuccess msg="Password updated successfully!"/>
      <AuthBtn onClick={() => onSwitch("login")}>Sign In →</AuthBtn>
    </AuthCard>
  );

  return (
    <AuthCard title="Set New Password" subtitle="Choose a strong password">
      <AuthError msg={error}/>
      <div style={{ marginBottom: 16 }}>
        <label style={{ display: "block", fontSize: 12, fontWeight: 700, color: "#9CA3AF", marginBottom: 6 }}>New Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Min. 12 characters" autoFocus
          style={{ width: "100%", padding: "12px 14px", background: "#1f2937", border: "1px solid #374151", borderRadius: 10, fontSize: 14, color: "#F9FAFB", outline: "none", boxSizing: "border-box" }}
          onFocus={e => e.target.style.borderColor = "#3B82F6"}
          onBlur={e  => e.target.style.borderColor = "#374151"}
        />
        <PasswordStrengthBar password={password}/>
      </div>
      <AuthInput label="Confirm New Password" type="password" value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="Re-enter password"/>
      <AuthBtn onClick={submit} loading={loading} disabled={!password || !confirm}>Update Password</AuthBtn>
    </AuthCard>
  );
}

// -- AuthGate - orchestrates all auth screens ----------------------------------
function AuthGate({ onAuth }) {
  // Check for reset token in URL
  const urlParams = new URLSearchParams(window.location.search);
  const resetToken = urlParams.get("token");

  const [screen,     setScreen]     = useState(resetToken ? "reset" : "login");
  const [mfaEmail,   setMfaEmail]   = useState("");
  const [verifyEmail, setVerifyEmail] = useState("");

  const switchTo = (s, email = "") => {
    setScreen(s);
    if (email) { setMfaEmail(email); setVerifyEmail(email); }
  };

  if (screen === "reset")    return <ResetPasswordScreen token={resetToken} onSwitch={switchTo}/>;
  if (screen === "register") return <RegisterScreen onSwitch={switchTo}/>;
  if (screen === "verify")   return <VerifyEmailScreen initialEmail={verifyEmail} onSwitch={switchTo}/>;
  if (screen === "mfa")      return <MFAScreen email={mfaEmail} onAuth={onAuth} onSwitch={switchTo}/>;
  if (screen === "forgot")   return <ForgotPasswordScreen onSwitch={switchTo}/>;
  return <LoginScreen onSwitch={switchTo} onMFA={(email) => switchTo("mfa", email)}/>;
}


// ═══════════════════════════════════════════════════════════════════════════════
// SIEM API KEY MANAGEMENT PAGE
// ═══════════════════════════════════════════════════════════════════════════════
function SiemKeysPage({ onBack }) {
  const [keys,        setKeys]        = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [creating,    setCreating]    = useState(false);
  const [newName,     setNewName]     = useState("");
  const [newKey,      setNewKey]      = useState(null);  // shown once after creation
  const [error,       setError]       = useState("");
  const [copied,      setCopied]      = useState(false);

  const fetchKeys = async () => {
    try {
      const r = await fetch(`${API_BASE}/siem/keys`, { headers: authHeaders() });
      if (r.ok) setKeys(await r.json());
    } catch(e) { setError("Failed to load keys"); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchKeys(); }, []);

  const createKey = async () => {
    if (!newName.trim()) return;
    setCreating(true); setError("");
    try {
      const r = await fetch(`${API_BASE}/siem/keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ name: newName.trim() }),
      });
      const d = await r.json();
      if (!r.ok) { setError(d.detail || "Failed to create key"); return; }
      setNewKey(d);
      setNewName("");
      fetchKeys();
    } catch(e) { setError("Network error"); }
    finally { setCreating(false); }
  };

  const revokeKey = async (id) => {
    if (!confirm("Revoke this API key? This cannot be undone.")) return;
    try {
      await fetch(`${API_BASE}/siem/keys/${id}`, { method: "DELETE", headers: authHeaders() });
      fetchKeys();
    } catch(e) { setError("Failed to revoke key"); }
  };

  const copyKey = () => {
    navigator.clipboard.writeText(newKey.raw_key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const s = { fontFamily: "system-ui, sans-serif", background: "#0b0f14", minHeight: "100vh", color: "#e0eaf4" };

  return (
    <div style={s}>
      {/* Header */}
      <div style={{ background: "#111827", borderBottom: "1px solid #1f2937", padding: "14px 24px", display: "flex", alignItems: "center", gap: 16 }}>
        <button onClick={onBack} style={{ background: "none", border: "none", color: "#6B7280", cursor: "pointer", fontSize: 13, fontWeight: 700 }}>← Back</button>
        <div style={{ fontSize: 13, fontWeight: 800, color: "#F9FAFB", letterSpacing: "0.05em" }}>SIEM API INTEGRATION</div>
        <div style={{ marginLeft: "auto", fontSize: 11, color: "#374151", fontFamily: "monospace" }}>POST /siem/enrich · X-API-Key header</div>
      </div>

      <div style={{ maxWidth: 860, margin: "0 auto", padding: "32px 24px" }}>

        {/* Intro */}
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 14, padding: "20px 24px", marginBottom: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: "#F9FAFB", marginBottom: 8 }}>REST API Pull - SIEM Integration</div>
          <div style={{ fontSize: 13, color: "#6B7280", lineHeight: 1.8, marginBottom: 16 }}>
            Generate an API key below and use it to submit IOCs programmatically from Splunk, Elastic SIEM, Microsoft Sentinel, IBM QRadar, or any REST-capable SOAR platform. Up to 10 IOCs per request, 60 requests/minute per key.
          </div>
          <div style={{ background: "#0d1117", borderRadius: 8, padding: "12px 16px", fontFamily: "monospace", fontSize: 12, color: "#10B981", lineHeight: 2 }}>
            <div style={{ color: "#4B5563" }}># Example curl request</div>
            <div>curl -X POST {API_BASE}/siem/enrich \</div>
            <div>{"  "}-H "X-API-Key: osint_your_key_here" \</div>
            <div>{"  "}-H "Content-Type: application/json" \</div>
            <div>{"  "}-d '{`{"iocs": ["185.220.101.35", "44d88612fea8a8f36de82e1278abb02f"]}`}'</div>
          </div>
        </div>

        {/* New key banner - shown once */}
        {newKey && (
          <div style={{ background: "#0a2e1a", border: "1px solid #065f26", borderRadius: 12, padding: "20px 24px", marginBottom: 24 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#34d399", marginBottom: 8 }}>✓ API Key Created - Copy it now</div>
            <div style={{ fontSize: 12, color: "#6B7280", marginBottom: 12 }}>This key will not be shown again. Store it securely in your SIEM or secrets manager.</div>
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <div style={{ flex: 1, background: "#111827", border: "1px solid #1f2937", borderRadius: 8, padding: "10px 14px", fontFamily: "monospace", fontSize: 13, color: "#34d399", wordBreak: "break-all" }}>
                {newKey.raw_key}
              </div>
              <button onClick={copyKey} style={{ padding: "10px 18px", background: copied ? "#065f26" : "#10B981", border: "none", borderRadius: 8, color: "#fff", fontWeight: 700, fontSize: 13, cursor: "pointer" }}>
                {copied ? "Copied!" : "Copy"}
              </button>
            </div>
            <button onClick={() => setNewKey(null)} style={{ marginTop: 12, background: "none", border: "none", color: "#4B5563", fontSize: 12, cursor: "pointer" }}>Dismiss</button>
          </div>
        )}

        {/* Create new key */}
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 14, padding: "20px 24px", marginBottom: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#F9FAFB", marginBottom: 16 }}>Create New API Key</div>
          {error && <div style={{ padding: "8px 12px", background: "#2d0f0f", border: "1px solid #7f1d1d", borderRadius: 8, fontSize: 13, color: "#F87171", marginBottom: 12 }}>{error}</div>}
          <div style={{ display: "flex", gap: 10 }}>
            <input
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder='e.g. "Splunk Production" or "QRadar Dev"'
              onKeyDown={e => e.key === "Enter" && createKey()}
              style={{ flex: 1, background: "#1f2937", border: "1px solid #374151", borderRadius: 8, padding: "10px 14px", fontSize: 13, color: "#F9FAFB", outline: "none", fontFamily: "system-ui" }}
            />
            <button onClick={createKey} disabled={creating || !newName.trim()}
              style={{ padding: "10px 24px", background: creating || !newName.trim() ? "#1f2937" : "linear-gradient(135deg,#2563EB,#3B82F6)", border: "none", borderRadius: 8, color: creating || !newName.trim() ? "#4B5563" : "#fff", fontWeight: 700, fontSize: 13, cursor: creating || !newName.trim() ? "default" : "pointer" }}>
              {creating ? "Creating..." : "Generate Key"}
            </button>
          </div>
        </div>

        {/* Keys list */}
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 14, overflow: "hidden" }}>
          <div style={{ padding: "16px 24px", borderBottom: "1px solid #1f2937", fontSize: 14, fontWeight: 700, color: "#F9FAFB" }}>
            Active API Keys ({keys.length})
          </div>
          {loading ? (
            <div style={{ padding: "32px", textAlign: "center", color: "#4B5563" }}>Loading...</div>
          ) : keys.length === 0 ? (
            <div style={{ padding: "32px", textAlign: "center", color: "#4B5563", fontSize: 13 }}>No API keys yet. Create one above to get started.</div>
          ) : (
            keys.map(k => (
              <div key={k.id} style={{ padding: "16px 24px", borderBottom: "1px solid #111827", display: "flex", alignItems: "center", gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#F9FAFB", marginBottom: 4 }}>{k.name}</div>
                  <div style={{ fontSize: 12, color: "#4B5563", fontFamily: "monospace" }}>
                    {k.key_prefix}••••••••••••••••••••••••••
                    <span style={{ marginLeft: 16 }}>Created {new Date(k.created_at).toLocaleDateString()}</span>
                    {k.last_used_at && <span style={{ marginLeft: 16 }}>Last used {new Date(k.last_used_at).toLocaleDateString()}</span>}
                    <span style={{ marginLeft: 16, color: "#3B82F6" }}>{k.requests_total} requests</span>
                  </div>
                </div>
                <button onClick={() => revokeKey(k.id)}
                  style={{ padding: "6px 14px", background: "transparent", border: "1px solid #7f1d1d", borderRadius: 6, color: "#EF4444", fontSize: 12, cursor: "pointer", fontWeight: 700 }}>
                  Revoke
                </button>
              </div>
            ))
          )}
        </div>

        {/* Integration guide */}
        <div style={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 14, padding: "20px 24px", marginTop: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#F9FAFB", marginBottom: 16 }}>SIEM Integration Examples</div>
          {[
            { name: "Splunk", desc: "Use REST API Input or Adaptive Response Action. POST indicators from notable events, write results to a lookup table.", color: "#3B82F6" },
            { name: "Elastic SIEM", desc: "Use Elastic Watcher or a Custom Connector. Call on rule trigger to enrich alerts with verdict and MITRE mapping.", color: "#F59E0B" },
            { name: "Microsoft Sentinel", desc: "Use a Logic App with HTTP action from an Automation Rule. Write enrichment results back as incident comments.", color: "#10B981" },
            { name: "IBM QRadar", desc: "Use a Custom Action script or SOAR integration. Call this endpoint and update offense custom properties.", color: "#A78BFA" },
          ].map(siem => (
            <div key={siem.name} style={{ display: "flex", gap: 12, marginBottom: 12, padding: "12px 14px", background: "#0d1117", borderRadius: 8, borderLeft: `3px solid ${siem.color}` }}>
              <div style={{ minWidth: 120, fontWeight: 700, color: siem.color, fontSize: 13 }}>{siem.name}</div>
              <div style={{ fontSize: 13, color: "#6B7280" }}>{siem.desc}</div>
            </div>
          ))}
          <div style={{ marginTop: 12, fontSize: 12, color: "#374151" }}>
            Response schema: verdict (malicious/suspicious/benign) · score (0-100) · confidence (%) · mitre_techniques ([T1566, ...]) · per-source scores
          </div>
        </div>

      </div>
    </div>
  );
}