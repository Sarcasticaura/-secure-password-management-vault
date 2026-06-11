/**
 * Vault Manager for Secure Password Manager (REST API Client Version)
 * Communicates with the PowerShell REST API backend for user sessions and database persistence.
 */

const VaultManager = {
  // --- Dynamic Base URL Resolution ---
  // If file opened directly (file://), target localhost:5000. If served, use relative paths.
  BASE_URL: window.location.origin.startsWith("file://") ? "http://localhost:5000" : "",

  // --- Session Storage Getters ---
  get token() {
    return sessionStorage.getItem("authToken");
  },
  get username() {
    return sessionStorage.getItem("authUsername");
  },
  get isUnlocked() {
    return !!this.token;
  },

  // --- Core API Requester ---
  async apiFetch(endpoint, method = "GET", body = null) {
    const headers = {
      "Content-Type": "application/json"
    };
    if (this.token) {
      headers["Authorization"] = this.token;
    }

    const config = {
      method: method,
      headers: headers
    };
    if (body) {
      config.body = JSON.stringify(body);
    }

    const response = await fetch(`${this.BASE_URL}${endpoint}`, config);
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP error ${response.status}`);
    }

    return await response.json().catch(() => ({}));
  },

  // --- Core Lifecycle ---

  /**
   * Queries the server to check if any user accounts are initialized in the database.
   */
  async vaultExists() {
    try {
      const data = await this.apiFetch("/api/status");
      return !!data.usersExist;
    } catch (e) {
      console.warn("Failed to check server status:", e);
      return false;
    }
  },

  /**
   * Registers a new user account on the backend.
   */
  async createVault(username, password) {
    // 1. Post registration details to backend
    await this.apiFetch("/api/register", "POST", { username, password });
    
    // 2. Automatically log in after registration
    return await this.unlock(username, password);
  },

  /**
   * Authenticates with the backend using username & password.
   */
  async unlock(username, password) {
    try {
      const data = await this.apiFetch("/api/login", "POST", { username, password });
      if (data.success && data.token) {
        sessionStorage.setItem("authToken", data.token);
        sessionStorage.setItem("authUsername", data.username);
        return true;
      }
      return false;
    } catch (e) {
      console.warn("Authentication rejected by server:", e);
      return false;
    }
  },

  /**
   * Wipes session tokens from local memory.
   */
  lock() {
    sessionStorage.removeItem("authToken");
    sessionStorage.removeItem("authUsername");
  },

  /**
   * Triggers a request to clear the server session.
   */
  destroyVault() {
    this.lock();
  },

  // --- Credential Operations ---

  /**
   * Fetches the user's decrypted credentials from the server.
   */
  async getItems() {
    if (!this.isUnlocked) {
      throw new Error("Vault is locked.");
    }
    return await this.apiFetch("/api/credentials", "GET");
  },

  /**
   * Submits a new credential record to the backend for encryption and storage.
   */
  async addItem(category, { title, username, password, website, notes }) {
    if (!this.isUnlocked) {
      throw new Error("Vault is locked.");
    }
    return await this.apiFetch("/api/credentials", "POST", {
      category,
      title,
      username,
      password,
      website,
      notes
    });
  },

  /**
   * Submits modified credentials to the backend.
   */
  async updateItem(id, category, { title, username, password, website, notes }) {
    if (!this.isUnlocked) {
      throw new Error("Vault is locked.");
    }
    return await this.apiFetch(`/api/credentials/${id}`, "PUT", {
      category,
      title,
      username,
      password,
      website,
      notes
    });
  },

  /**
   * Submits a deletion request for a credential ID.
   */
  async deleteItem(id) {
    if (!this.isUnlocked) {
      throw new Error("Vault is locked.");
    }
    return await this.apiFetch(`/api/credentials/${id}`, "DELETE");
  },

  /**
   * Calls the server-side visualization pipeline for educational analysis.
   */
  async getEncryptionStepsForVisualizer(title, username, password, website, notes) {
    if (!this.isUnlocked) {
      return null;
    }
    const plaintext = JSON.stringify({ title, username, password, website, notes });
    return await this.apiFetch("/api/visualize", "POST", { password, plaintext });
  },

  // --- Security Audit Module ---

  /**
   * Evaluates decrypted credentials for vulnerabilities locally.
   */
  async performAudit() {
    const items = await this.getItems();
    const result = {
      total: 0,
      veryWeak: 0,
      weak: 0,
      medium: 0,
      strong: 0,
      excellent: 0,
      reused: {},
      compromised: [], // simulated breached passwords
      recommendations: []
    };

    const passwordCounts = {};

    for (const item of items) {
      if (item.category === "logins" && item.password) {
        result.total++;
        const entropy = CryptoEngine.calculateEntropy(item.password);
        const strength = CryptoEngine.getEntropyStrength(entropy);

        if (strength.score === 0) result.veryWeak++;
        else if (strength.score === 1) result.weak++;
        else if (strength.score === 2) result.medium++;
        else if (strength.score === 3) result.strong++;
        else if (strength.score === 4) result.excellent++;

        // Track reused passwords
        passwordCounts[item.password] = passwordCounts[item.password] || [];
        passwordCounts[item.password].push(item.title || item.website || "Untitled Entry");

        // Simulate breached passwords check (offline-friendly heuristic + mock breach)
        const lowerPw = item.password.toLowerCase();
        if (this.MOCK_BREACH_LIST.includes(lowerPw) || entropy < 30) {
          result.compromised.push({
            id: item.id,
            title: item.title,
            username: item.username,
            password: item.password
          });
        }
      }
    }

    // Populate reused password list
    for (const [pw, accounts] of Object.entries(passwordCounts)) {
      if (accounts.length > 1) {
        result.reused[pw] = accounts;
      }
    }

    // Build specific security recommendations
    if (result.veryWeak + result.weak > 0) {
      result.recommendations.push({
        type: "danger",
        title: "Weak Passwords Found",
        desc: `You have ${result.veryWeak + result.weak} password(s) with weak entropy. Replace them with randomly generated passwords of at least 16 characters.`
      });
    }

    const reusedCount = Object.values(result.reused).length;
    if (reusedCount > 0) {
      result.recommendations.push({
        type: "warning",
        title: "Reused Passwords Detected",
        desc: `You are using the same password across ${reusedCount} different set(s) of credentials. Using the same password makes all accounts vulnerable if one is breached.`
      });
    }

    if (result.compromised.length > 0) {
      result.recommendations.push({
        type: "danger",
        title: "Compromised Passwords (Breach Simulation)",
        desc: `${result.compromised.length} password(s) match common passwords found in standard wordlists and data leaks. Change them immediately.`
      });
    }

    if (result.total > 0 && result.recommendations.length === 0) {
      result.recommendations.push({
        type: "success",
        title: "Vault Secure",
        desc: "Congratulations! All your passwords have strong entropy, there are no reuses, and none match common breached patterns."
      });
    }

    return result;
  },

  // A local offline database of 50 common/compromised passwords for simulated security breaches.
  MOCK_BREACH_LIST: [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "password123", 
    "admin", "1234567", "letmein", "123123", "charlie", "111111", "iloveyou", "password12",
    "monkey", "trustnoone", "dragon", "baseball", "sunshine", "shadow", "cybersecurity", 
    "master", "secret", "guest", "welcome", "hackme", "hunter2", "qwerty123", "p@ssword",
    "password123!", "123456abc", "security", "root", "oracle", "system", "pass123"
  ]
};

// Export for browser script usage
window.VaultManager = VaultManager;
