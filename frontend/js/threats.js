/**
 * PhishGuard AI - All Risks & Threats Catalog Controller
 * Renders all phishing, structural, network, and domain-existence threats
 * with live detection counts, search, and severity filtering.
 */

import { API } from "./api.js";

export function initThreats() {
  const grid = document.getElementById("threatsGrid");
  const searchInput = document.getElementById("threatSearchInput");
  const filterButtons = document.querySelectorAll(".threat-filter-btn");
  const visibleCountElem = document.getElementById("threatsVisibleCount");

  let allThreats = [];
  let activeSeverity = "";
  let searchQuery = "";

  async function loadThreats() {
    if (!grid) return;
    try {
      const catalog = await API.getThreats();
      allThreats = catalog.threats || [];

      const breakdown = catalog.severity_breakdown || {};
      const totalElem = document.getElementById("threatTotalCount");
      const highElem = document.getElementById("threatHighCount");
      const medElem = document.getElementById("threatMediumCount");
      const lowElem = document.getElementById("threatLowCount");

      if (totalElem) totalElem.textContent = catalog.total_threats ?? allThreats.length;
      if (highElem) highElem.textContent = breakdown.HIGH ?? 0;
      if (medElem) medElem.textContent = breakdown.MEDIUM ?? 0;
      if (lowElem) lowElem.textContent = breakdown.LOW ?? 0;

      renderThreats();
    } catch (err) {
      console.error("Failed to load threats catalog:", err);
      grid.innerHTML = `
        <div class="glass-card" style="grid-column: 1 / -1; color: var(--color-danger);">
          Unable to load threat catalog from backend API.
        </div>
      `;
    }
  }

  function renderThreats() {
    if (!grid) return;
    const query = searchQuery.trim().toLowerCase();

    const filtered = allThreats.filter((threat) => {
      if (activeSeverity && threat.severity !== activeSeverity) {
        return false;
      }
      if (query) {
        const haystack = [
          threat.name,
          threat.category,
          threat.description,
          threat.feature_key,
          threat.example,
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(query);
      }
      return true;
    });

    if (visibleCountElem) {
      visibleCountElem.textContent = `${filtered.length} threat${filtered.length === 1 ? "" : "s"}`;
    }

    if (filtered.length === 0) {
      grid.innerHTML = `
        <div class="glass-card" style="grid-column: 1 / -1; text-align: center; color: var(--text-muted);">
          No threat definitions match your current filter.
        </div>
      `;
      return;
    }

    grid.innerHTML = "";
    filtered.forEach((threat) => {
      const card = document.createElement("article");
      card.className = "glass-card threat-card";
      const sevClass = (threat.severity || "LOW").toLowerCase();
      const detectedCount = threat.detected_count || 0;

      card.innerHTML = `
        <div class="threat-card-header">
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <span class="severity-tag ${sevClass}">${escapeHtml(threat.severity)}</span>
            <span class="threat-category-pill">${escapeHtml(threat.category)}</span>
          </div>
          <span class="threat-hit-badge ${detectedCount > 0 ? "active" : ""}">
            ${detectedCount} scan hit${detectedCount === 1 ? "" : "s"}
          </span>
        </div>

        <h3 class="threat-card-title">${escapeHtml(threat.name)}</h3>
        <p class="threat-card-desc">${escapeHtml(threat.description)}</p>

        <div class="threat-example-box">
          <span class="threat-box-label">Example Pattern</span>
          <code>${escapeHtml(threat.example)}</code>
        </div>

        <div class="threat-mitigation-box">
          <span class="threat-box-label">Defense &amp; Verification</span>
          <span>${escapeHtml(threat.mitigation)}</span>
        </div>

        <div class="threat-card-footer">
          <span>Signal Key:</span>
          <code>${escapeHtml(threat.feature_key)}</code>
        </div>
      `;
      grid.appendChild(card);
    });
  }

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      searchQuery = searchInput.value;
      renderThreats();
    });
  }

  filterButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeSeverity = btn.getAttribute("data-severity") || "";
      renderThreats();
    });
  });

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str ?? "");
    return div.innerHTML;
  }

  window.addEventListener("scanCompleted", () => {
    loadThreats();
  });

  window.refreshThreats = loadThreats;
  loadThreats();
}
