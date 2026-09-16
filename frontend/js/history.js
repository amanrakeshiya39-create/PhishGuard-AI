/**
 * PhishGuard AI - History Controller
 * Fetches, filters, searches, and displays past scan audit trails.
 */

import { API } from "./api.js";

export function initHistory() {
  const tbody = document.getElementById("historyTableBody");
  const searchInput = document.getElementById("historySearchInput");
  const filterBtns = document.querySelectorAll(".filter-btn");
  const totalElem = document.getElementById("historyTotalCount");

  let currentClassification = "";
  let currentSearch = "";
  let searchTimeout = null;

  async function loadHistory() {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 32px; color: var(--text-muted);">
          Loading scan history...
        </td>
      </tr>
    `;

    try {
      const res = await API.getHistory({
        limit: 50,
        skip: 0,
        classification: currentClassification,
        search: currentSearch
      });

      if (totalElem) totalElem.textContent = `${res.total} record(s)`;
      renderHistoryTable(res.items);
    } catch (err) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 32px; color: var(--color-danger);">
            Failed to load history: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  function renderHistoryTable(items) {
    tbody.innerHTML = "";

    if (!items || items.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">
            No previous scans found matching the criteria.
          </td>
        </tr>
      `;
      return;
    }

    items.forEach((item) => {
      const tr = document.createElement("tr");

      let badgeClass = "safe";
      if (item.classification === "Phishing") badgeClass = "phishing";
      else if (item.classification === "Suspicious") badgeClass = "suspicious";

      const dateStr = item.scanned_at
        ? new Date(item.scanned_at).toLocaleString(undefined, {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })
        : "Recent";

      tr.innerHTML = `
        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <a href="#" class="history-url-link" data-url="${escapeHtml(item.url)}" title="${escapeHtml(item.url)}" style="color: var(--cyan-primary); text-decoration: none; font-family: var(--font-mono);">
            ${escapeHtml(item.url)}
          </a>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(item.domain)}</div>
        </td>
        <td>
          <span style="font-family: var(--font-mono); font-weight: 700; color: ${getScoreColor(item.risk_score)};">
            ${item.risk_score} / 100
          </span>
        </td>
        <td>
          <span class="badge-classification ${badgeClass}" style="padding: 3px 10px; font-size: 0.75rem;">
            ${escapeHtml(item.classification)}
          </span>
        </td>
        <td style="font-size: 0.85rem; color: var(--text-secondary);">
          ${Math.round(item.confidence * 100)}%
        </td>
        <td style="font-size: 0.82rem; color: var(--text-muted); white-space: nowrap;">
          ${escapeHtml(dateStr)}
        </td>
        <td style="text-align: right; white-space: nowrap;">
          <button class="btn-icon btn-rescan" data-url="${escapeHtml(item.url)}" title="Scan URL Again">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          </button>
          <button class="btn-icon btn-delete" data-id="${escapeHtml(item.id)}" title="Delete record">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </td>
      `;

      tbody.appendChild(tr);
    });

    // Attach event listeners to row buttons
    tbody.querySelectorAll(".history-url-link, .btn-rescan").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const targetUrl = btn.getAttribute("data-url");
        const scannerTab = document.querySelector('[data-tab="scanner"]');
        const urlInput = document.getElementById("urlInput");
        if (scannerTab && urlInput) {
          scannerTab.click();
          urlInput.value = targetUrl;
          document.getElementById("urlScanForm").dispatchEvent(new Event("submit"));
        }
      });
    });

    tbody.querySelectorAll(".btn-delete").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        if (confirm("Remove this scan entry from history?")) {
          try {
            await API.deleteScan(id);
            loadHistory();
            window.dispatchEvent(new CustomEvent("scanCompleted"));
          } catch (err) {
            alert(err.message || "Failed to delete item.");
          }
        }
      });
    });
  }

  // Filter Buttons Click
  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentClassification = btn.getAttribute("data-filter") || "";
      loadHistory();
    });
  });

  // Debounced Search Input
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentSearch = searchInput.value.trim();
      loadHistory();
    }, 300);
  });

  // Auto-refresh when new scan completes
  window.addEventListener("scanCompleted", () => {
    loadHistory();
  });

  function getScoreColor(score) {
    if (score >= 70) return "var(--color-danger)";
    if (score >= 35) return "var(--color-suspicious)";
    return "var(--color-safe)";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // Initial load
  loadHistory();
}
