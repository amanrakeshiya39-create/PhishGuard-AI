/**
 * PhishGuard AI - Dashboard Analytics Controller
 * Visualizes overall threat detection metrics and risk distribution.
 */

import { API } from "./api.js?v=4";

export function initDashboard() {
  async function loadDashboardStats() {
    try {
      const stats = await API.getStats();
      renderStats(stats);
    } catch (err) {
      console.error("Dashboard error:", err);
    }
  }

  function renderStats(stats) {
    // 1. Primary Metrics
    document.getElementById("statTotalScans").textContent = stats.total_scans;
    document.getElementById("statPhishingCount").textContent = stats.phishing_count;
    document.getElementById("statPhishingPct").textContent = `${stats.phishing_percentage}% of total`;

    document.getElementById("statSuspiciousCount").textContent = stats.suspicious_count;
    document.getElementById("statSuspiciousPct").textContent = `${stats.suspicious_percentage}% of total`;

    document.getElementById("statLowRiskCount").textContent = stats.low_risk_count;
    document.getElementById("statLowRiskPct").textContent = `${stats.low_risk_percentage}% of total`;

    document.getElementById("statAvgScore").textContent = stats.average_risk_score;

    // 2. Segmented Distribution Bar
    const segSafe = document.getElementById("distSegmentSafe");
    const segSusp = document.getElementById("distSegmentSuspicious");
    const segDang = document.getElementById("distSegmentDanger");

    if (stats.total_scans > 0) {
      segSafe.style.width = `${stats.low_risk_percentage}%`;
      segSusp.style.width = `${stats.suspicious_percentage}%`;
      segDang.style.width = `${stats.phishing_percentage}%`;
    } else {
      segSafe.style.width = "0%";
      segSusp.style.width = "0%";
      segDang.style.width = "0%";
    }

    // 3. Top Flagged Indicators List
    const factorsList = document.getElementById("dashboardTopFactors");
    factorsList.innerHTML = "";

    const topFactors = stats.top_flagged_factors || [];
    if (topFactors.length === 0) {
      factorsList.innerHTML = `
        <div style="color: var(--text-muted); font-size: 0.9rem; padding: 12px 0;">
          No threat indicator triggers recorded yet. Start scanning URLs to build telemetry!
        </div>
      `;
    } else {
      topFactors.forEach((item) => {
        const factorDiv = document.createElement("div");
        factorDiv.className = "factor-item";
        factorDiv.style.justifyContent = "space-between";
        factorDiv.style.alignItems = "center";
        factorDiv.innerHTML = `
          <div style="font-weight: 600; font-size: 0.9rem; color: var(--text-primary);">
            ${escapeHtml(item.factor)}
          </div>
          <span class="feature-value-badge" style="color: var(--cyan-primary);">
            ${item.count} triggered
          </span>
        `;
        factorsList.appendChild(factorDiv);
      });
    }

    // Database Connection Badge
    const dbIndicator = document.getElementById("dbStatusIndicator");
    if (dbIndicator) {
      if (stats.is_database_connected) {
        dbIndicator.innerHTML = `<span class="status-dot"></span> <span>MongoDB Connected</span>`;
      } else {
        dbIndicator.innerHTML = `<span class="status-dot offline"></span> <span>In-Memory Fallback Active</span>`;
      }
    }
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  window.addEventListener("scanCompleted", () => {
    loadDashboardStats();
  });

  // Export for manual trigger on tab change
  window.refreshDashboard = loadDashboardStats;

  loadDashboardStats();
}
