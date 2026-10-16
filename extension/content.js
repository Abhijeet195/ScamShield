/**
 * ScamShield In-Page Pre-Click Interception Content Script
 * Intercepts navigation on suspicious, shortened, or phishing links before the browser visits them.
 */

const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "goo.gl", "lnkd.in",
  "rebrand.ly", "bl.ink", "t.ly", "qr.ae", "s.id", "v.gd"
]);

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
  ".work", ".loan", ".click", ".download", ".racing", ".accountant",
  ".live", ".shop", ".site", ".online", ".vip", ".cc", ".to", ".info",
  ".monster", ".rest", ".cam", ".icu"
];

function isIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function evaluateLinkHeuristics(href) {
  try {
    const parsed = new URL(href);
    const host = parsed.hostname.toLowerCase();
    const flags = [];
    let risk = "low";

    if (parsed.protocol === "http:") {
      flags.push("Unencrypted HTTP connection");
    }

    if (isIpAddress(host)) {
      flags.push("Numeric IP address destination");
      risk = "high";
    }

    if (KNOWN_SHORTENERS.has(host) || Array.from(KNOWN_SHORTENERS).some(s => host.endsWith("." + s))) {
      flags.push("Shortened URL service concealing real destination");
      if (risk !== "high") risk = "medium";
    }

    for (const tld of SUSPICIOUS_TLDS) {
      if (host.endsWith(tld)) {
        flags.push(`Uses high-risk top-level domain (${tld})`);
        risk = "high";
        break;
      }
    }

    if (parsed.pathname.endsWith(".apk") || parsed.pathname.endsWith(".exe")) {
      flags.push("Direct executable/package download (.apk/.exe)");
      risk = "high";
    }

    return { risk, flags, parsed };
  } catch (e) {
    return { risk: "low", flags: [], parsed: null };
  }
}

function showPreClickModal(url, risk, flags, onProceed) {
  // Remove existing modal if present
  const existing = document.getElementById("scamshield-modal-root");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "scamshield-modal-root";
  overlay.className = "scamshield-modal-overlay";

  const flagsHtml = flags.map(f => `<li>${f}</li>`).join("");

  overlay.innerHTML = `
    <div class="scamshield-modal-card">
      <div class="scamshield-modal-header">
        <div class="scamshield-modal-icon">⚠️</div>
        <div>
          <div class="scamshield-modal-subtitle">Pre-Click Warning Intercepted</div>
          <h3 class="scamshield-modal-title">Suspicious Link Detected</h3>
        </div>
      </div>
      <div class="scamshield-modal-body">
        <p>ScamShield prevented an immediate redirect to an unverified or potentially deceptive link.</p>
        <div class="scamshield-link-preview">${url}</div>
        <div class="scamshield-flags-box">
          <strong>Identified Threat Factors:</strong>
          <ul>${flagsHtml}</ul>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin: 8px 0 0 0;">
          Phishing messages frequently use shortened URLs and unverified domains to steal credentials or install malicious packages.
        </p>
      </div>
      <div class="scamshield-actions">
        <button id="scamshield-abort-btn" class="scamshield-btn-safe">Stay Safe (Cancel Navigation)</button>
        <button id="scamshield-proceed-btn" class="scamshield-btn-danger">Proceed Anyway (Unsafe)</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("scamshield-abort-btn").addEventListener("click", () => {
    overlay.remove();
  });

  document.getElementById("scamshield-proceed-btn").addEventListener("click", () => {
    overlay.remove();
    onProceed();
  });
}

// Global click interceptor
document.addEventListener("click", (event) => {
  const anchor = event.target.closest("a");
  if (!anchor || !anchor.href) return;

  const href = anchor.href;
  // Ignore hash links and same-page anchors
  if (href.startsWith("#") || href.startsWith("javascript:")) return;

  const { risk, flags } = evaluateLinkHeuristics(href);

  // If high or medium risk, intercept navigation
  if (risk === "high" || (risk === "medium" && flags.length > 0)) {
    event.preventDefault();
    event.stopPropagation();

    showPreClickModal(href, risk, flags, () => {
      // User explicitly elected to proceed
      window.location.href = href;
    });
  }
}, true);
