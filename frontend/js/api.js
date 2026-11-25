/**
 * PhishGuard AI - Centralized REST API Client
 * Automatically connects to backend API whether served directly or via file.
 */

const API_BASE_URL = (() => {
  // If running directly on a different port or file protocol, target default backend port 8000
  if (window.location.protocol === "file:" || window.location.port === "5500" || window.location.port === "3000") {
    return "http://localhost:8000/api/v1";
  }
  return "/api/v1";
})();

export const API = {
  /**
   * Health Check
   */
  async getHealth() {
    try {
      const res = await fetch(`${API_BASE_URL}/health`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn("Backend health check warning:", err);
      return { status: "unreachable", ml_model_loaded: false, database_connected: false };
    }
  },

  /**
   * Submits a URL for scanning
   */
  async scanURL(url) {
    const res = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Failed to scan URL. Please verify format.");
    }
    return data.data;
  },

  /**
   * Fetches scan history
   */
  async getHistory({ limit = 20, skip = 0, classification = "", search = "" } = {}) {
    const params = new URLSearchParams({ limit, skip });
    if (classification) params.append("classification", classification);
    if (search) params.append("search", search);

    const res = await fetch(`${API_BASE_URL}/history?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load history.");
    return await res.json();
  },

  /**
   * Fetches full details for a single scan
   */
  async getScanDetails(id) {
    const res = await fetch(`${API_BASE_URL}/scan/${id}`);
    if (!res.ok) throw new Error("Scan record not found.");
    const data = await res.json();
    return data.data;
  },

  /**
   * Deletes a scan record
   */
  async deleteScan(id) {
    const res = await fetch(`${API_BASE_URL}/history/${id}`, {
      method: "DELETE"
    });
    if (!res.ok) throw new Error("Failed to delete record.");
    return await res.json();
  },

  /**
   * Fetches aggregated dashboard metrics
   */
  async getStats() {
    const res = await fetch(`${API_BASE_URL}/stats`);
    if (!res.ok) throw new Error("Failed to load statistics.");
    const data = await res.json();
    return data.data;
  },

  /**
   * Fetches full threat catalog and live detection counts
   */
  async getThreats() {
    const res = await fetch(`${API_BASE_URL}/threats`);
    if (!res.ok) throw new Error("Failed to load threats catalog.");
    const data = await res.json();
    return data.data;
  }
};
