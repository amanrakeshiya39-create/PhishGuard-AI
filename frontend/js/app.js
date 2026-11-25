/**
 * PhishGuard AI - Main Frontend Application Entrypoint
 * Coordinates tabs, system health telemetry, and module initialization.
 */

import { API } from "./api.js";
import { initScanner } from "./scanner.js";
import { initHistory } from "./history.js";
import { initDashboard } from "./dashboard.js";
import { initThreats } from "./threats.js";

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Subsystems
  initScanner();
  initHistory();
  initDashboard();
  initThreats();

  // 2. Tab Navigation
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabViews = document.querySelectorAll(".tab-view");

  navTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetTabId = tab.getAttribute("data-tab");

      navTabs.forEach((t) => t.classList.remove("active"));
      tabViews.forEach((view) => view.classList.remove("active"));

      tab.classList.add("active");
      const targetView = document.getElementById(`${targetTabId}View`);
      if (targetView) {
        targetView.classList.add("active");
      }

      // Trigger targeted refresh on tab switch
      if (targetTabId === "dashboard" && window.refreshDashboard) {
        window.refreshDashboard();
      } else if (targetTabId === "threats" && window.refreshThreats) {
        window.refreshThreats();
      }
    });
  });

  // 3. System Health Monitor
  async function checkSystemHealth() {
    const statusDot = document.getElementById("headerStatusDot");
    const statusText = document.getElementById("headerStatusText");

    const health = await API.getHealth();
    if (health.status === "healthy" && health.ml_model_loaded) {
      statusDot.className = "status-dot";
      statusText.textContent = "AI Engine Active";
    } else {
      statusDot.className = "status-dot offline";
      statusText.textContent = "Engine Offline";
    }
  }

  checkSystemHealth();
  // Poll health every 30 seconds
  setInterval(checkSystemHealth, 30000);
});
