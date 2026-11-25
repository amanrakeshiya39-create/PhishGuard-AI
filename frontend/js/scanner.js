/**
 * PhishGuard AI - Scanner Controller
 * Manages URL submission, animated risk gauge, diagnostics, and feature inspection.
 */

import { API } from "./api.js";

const CIRCUMFERENCE = 565.48; // 2 * PI * 90

export function initScanner() {
  const form = document.getElementById("urlScanForm");
  const input = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearInputBtn");
  const scanBtn = document.getElementById("scanBtn");
  const btnSpinner = document.getElementById("btnSpinner");
  const btnText = document.getElementById("btnText");
  const errorAlert = document.getElementById("scanErrorAlert");
  const errorMsg = document.getElementById("scanErrorMessage");
  const resultsContainer = document.getElementById("resultsContainer");

  // Clear button toggle
  input.addEventListener("input", () => {
    clearBtn.style.display = input.value.trim() ? "flex" : "none";
    hideError();
  });

  clearBtn.addEventListener("click", () => {
    input.value = "";
    clearBtn.style.display = "none";
    input.focus();
    hideError();
  });

  // Form submission
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) {
      showError("Please enter a URL or domain name to scan.");
      return;
    }
    await executeScan(url);
  });

  // Handle Quick Sample Chips
  document.querySelectorAll(".sample-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.getAttribute("data-url");
      input.value = sampleUrl;
      clearBtn.style.display = "flex";
      executeScan(sampleUrl);
    });
  });

  // Feature Inspector Accordion Toggle
  const toggleBtn = document.getElementById("inspectorToggleBtn");
  const tableWrapper = document.getElementById("inspectorTableWrapper");
  const toggleArrow = document.getElementById("inspectorArrow");

  if (toggleBtn && tableWrapper) {
    toggleBtn.addEventListener("click", () => {
      const isHidden = tableWrapper.style.display === "none";
      tableWrapper.style.display = isHidden ? "block" : "none";
      toggleArrow.textContent = isHidden ? "▲" : "▼";
    });
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorAlert.style.display = "flex";
  }

  function hideError() {
    errorAlert.style.display = "none";
  }

  async function executeScan(url) {
    hideError();
    scanBtn.disabled = true;
    btnSpinner.style.display = "inline-block";
    btnText.textContent = "Analyzing...";

    try {
      const data = await API.scanURL(url);
      renderResults(data);
      resultsContainer.style.display = "block";
      resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
      // Notify history tab to refresh if needed
      window.dispatchEvent(new CustomEvent("scanCompleted"));
    } catch (err) {
      showError(err.message || "Analysis failed. Please check the URL format.");
    } finally {
      scanBtn.disabled = false;
      btnSpinner.style.display = "none";
      btnText.textContent = "Analyze Risk";
    }
  }

  function renderResults(data) {
    const score = data.risk_score;
    const classification = data.classification;

    // 1. Animated Score Counter
    const scoreElem = document.getElementById("gaugeScoreValue");
    animateValue(scoreElem, 0, score, 1000);

    // 2. Circular Gauge SVG
    const progressCircle = document.getElementById("gaugeProgressCircle");
    const offset = CIRCUMFERENCE * (1 - score / 100);
    progressCircle.style.strokeDashoffset = offset;

    // Gauge Color Palette
    let strokeColor = "var(--color-safe)";
    let badgeClass = "safe";
    let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>`;

    if (score >= 70 || classification === "Phishing") {
      strokeColor = "var(--color-danger)";
      badgeClass = "phishing";
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else if (score >= 35 || classification === "Suspicious") {
      strokeColor = "var(--color-suspicious)";
      badgeClass = "suspicious";
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    }

    progressCircle.style.stroke = strokeColor;

    // 3. Classification Badge
    const badge = document.getElementById("classificationBadge");
    badge.className = `badge-classification ${badgeClass}`;
    badge.innerHTML = `${iconSvg} <span>${classification}</span>`;

    // 4. Confidence
    const confElem = document.getElementById("confidenceText");
    confElem.textContent = `Model Confidence: ${(data.confidence * 100).toFixed(0)}%`;

    // 5. Target Overview & URL Existence
    document.getElementById("targetUrlText").textContent = data.url;
    renderUrlExistence(data.url_existence);
    document.getElementById("diagnosticSummaryText").textContent = data.explanation.summary;

    // 6. Risk Factors
    const factorsList = document.getElementById("riskFactorsList");
    factorsList.innerHTML = "";

    const factors = data.explanation.risk_factors || [];
    if (factors.length === 0) {
      factorsList.innerHTML = `
        <div class="no-factors-badge">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          <span>No malicious or abnormal heuristic markers were flagged for this target.</span>
        </div>
      `;
    } else {
      factors.forEach((f) => {
        const item = document.createElement("div");
        item.className = "factor-item";
        const sevClass = (f.severity || "LOW").toLowerCase();
        item.innerHTML = `
          <span class="severity-tag ${sevClass}">${f.severity}</span>
          <div class="factor-details">
            <div class="factor-title">${escapeHtml(f.factor)}</div>
            <div class="factor-desc">${escapeHtml(f.description)}</div>
          </div>
        `;
        factorsList.appendChild(item);
      });
    }

    // 7. 20-Feature Inspector
    renderFeatureTable(data.features);

    // 8. Disclaimer
    document.getElementById("disclaimerText").textContent = data.disclaimer;
  }

  function renderUrlExistence(existence) {
    const badge = document.getElementById("urlExistenceBadge");
    const detail = document.getElementById("urlExistenceDetail");
    const meta = document.getElementById("urlExistenceMeta");
    if (!badge || !detail || !meta) return;

    if (!existence) {
      badge.className = "existence-pill unknown";
      badge.textContent = "Not Checked";
      detail.textContent = "Live URL existence status was not included in this record.";
      meta.innerHTML = "";
      return;
    }

    let pillClass = "unknown";
    if (existence.exists === true) {
      pillClass = existence.http_status && existence.http_status >= 400 ? "restricted" : "exists";
    } else if (existence.exists === false) {
      pillClass = "missing";
    }

    badge.className = `existence-pill ${pillClass}`;
    badge.textContent = existence.status || "Unknown";
    detail.textContent = existence.detail || "";

    const metaParts = [];
    metaParts.push(`DNS: ${existence.dns_resolved ? "Resolved" : "Not Resolved"}`);
    if (existence.resolved_ip) metaParts.push(`IP: ${existence.resolved_ip}`);
    if (existence.http_status !== null && existence.http_status !== undefined) {
      metaParts.push(`HTTP: ${existence.http_status}`);
    }
    if (existence.response_time_ms !== null && existence.response_time_ms !== undefined) {
      metaParts.push(`Latency: ${existence.response_time_ms} ms`);
    }

    meta.innerHTML = metaParts
      .map((item) => `<span class="existence-meta-chip">${escapeHtml(item)}</span>`)
      .join("");
  }

  function renderFeatureTable(features) {
    const tbody = document.getElementById("featuresTableBody");
    tbody.innerHTML = "";

    const friendlyNames = {
      url: "Normalized URL String",
      hostname: "Extracted Hostname",
      url_length: "Total URL Length",
      hostname_length: "Hostname Character Length",
      domain_length: "Domain Character Length",
      path_length: "URL Path Length",
      query_length: "Query String Length",
      has_ip: "Raw IP Hostname",
      count_dots: "Total Dots (.)",
      count_hyphens: "Total Hyphens (-)",
      count_digits: "Total Numeric Digits",
      count_special_chars: "Special Character Count",
      has_at_symbol: "Credential '@' Symbol Present",
      count_at: "Credential '@' Symbol Count",
      count_question: "Query Delimiters (?)",
      count_equal: "Parameter Operators (=)",
      count_slash: "Path Delimiters (/)",
      subdomain_count: "Subdomain Nesting Level",
      count_subdomains: "Subdomain Nesting Level",
      has_https: "HTTPS Protocol Active",
      has_double_slash_redirect: "Double Slash (//) In Path",
      has_suspicious_keywords: "Suspicious Keyword Flag",
      suspicious_keyword_count: "Suspicious Keyword Count",
      detected_keywords: "Matched Phishing Keywords",
      has_suspicious_tld: "Abuse-Prone TLD (.xyz, .top, etc.)",
      url_entropy: "Shannon Character Entropy",
      digits_ratio: "Numeric Digit Density",
      has_non_standard_port: "Explicit Non-Standard Port",
      is_shortened: "Known URL Shortener",
      longest_token_length: "Longest Contiguous Token",
      is_punycode: "Punycode (xn--) Homograph",
    };

    for (const [key, val] of Object.entries(features)) {
      const row = document.createElement("tr");
      const label = friendlyNames[key] || key;
      let displayVal = val;
      if (typeof val === "number" && !Number.isInteger(val)) {
        displayVal = val.toFixed(4);
      }
      if (val === 1 && (key.startsWith("has_") || key.startsWith("is_"))) {
        displayVal = "Yes (Flagged)";
      } else if (val === 0 && (key.startsWith("has_") || key.startsWith("is_"))) {
        displayVal = "No (Normal)";
      }

      row.innerHTML = `
        <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(key)}</td>
        <td>${escapeHtml(label)}</td>
        <td><span class="feature-value-badge">${escapeHtml(String(displayVal))}</span></td>
      `;
      tbody.appendChild(row);
    }
  }

  function animateValue(elem, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      elem.textContent = Math.floor(progress * (end - start) + start);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        elem.textContent = end;
      }
    };
    window.requestAnimationFrame(step);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
}
