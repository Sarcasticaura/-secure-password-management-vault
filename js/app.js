/**
 * Aura Vault Application Controller (REST API Client Version)
 * Coordinates UI states, navigation tabs, session timeouts, and handles API data binds.
 */

document.addEventListener("DOMContentLoaded", () => {
  // --- UI Elements ---
  const elAuthOverlay = document.getElementById("auth-overlay");
  const elAuthSetupFlow = document.getElementById("auth-setup-flow");
  const elAuthLoginFlow = document.getElementById("auth-login-flow");
  const elAppContainer = document.getElementById("app-container");
  
  const elSetupForm = document.getElementById("setup-form");
  const elSetupUsername = document.getElementById("setup-username");
  const elSetupPassword = document.getElementById("setup-password");
  const elSetupPasswordConfirm = document.getElementById("setup-password-confirm");
  const elSetupPwStrength = document.getElementById("setup-pw-strength");
  
  const elLoginForm = document.getElementById("login-form");
  const elLoginUsername = document.getElementById("login-username");
  const elLoginPassword = document.getElementById("login-password");
  const elBtnResetVaultWarning = document.getElementById("btn-reset-vault-warning");
  
  const elNavItems = document.querySelectorAll(".nav-item");
  const elViews = document.querySelectorAll(".app-view");
  const elAutolockTimer = document.getElementById("autolock-timer");
  const elBtnLockVaultAction = document.getElementById("btn-lock-vault-action");
  
  const elVaultSearch = document.getElementById("vault-search");
  const elFilterBtns = document.querySelectorAll(".filter-btn");
  const elVaultEmptyState = document.getElementById("vault-empty-state");
  const elVaultList = document.getElementById("vault-list");
  const elVaultDetailPanel = document.getElementById("vault-detail-panel");
  const elDetailContent = document.getElementById("detail-content");
  
  const elBtnAddCredentialModal = document.getElementById("btn-add-credential-modal");
  const elCredentialModal = document.getElementById("credential-modal");
  const elCredentialForm = document.getElementById("credential-form");
  const elModalTitle = document.getElementById("modal-title");
  const elBtnCloseModal = document.getElementById("btn-close-modal");
  const elBtnCancelModal = document.getElementById("btn-cancel-modal");
  const elCredId = document.getElementById("cred-id");
  const elCredCategory = document.getElementById("cred-category");
  const elCredTitle = document.getElementById("cred-title");
  const elFieldsLoginOnly = document.getElementById("fields-login-only");
  const elCredUsername = document.getElementById("cred-username");
  const elCredPassword = document.getElementById("cred-password");
  const elBtnCredPwShow = document.getElementById("btn-cred-pw-show");
  const elBtnCredPwGenerate = document.getElementById("btn-cred-pw-generate");
  const elCredPwStrength = document.getElementById("cred-pw-strength");
  const elCredWebsite = document.getElementById("cred-website");
  const elFieldsNotesOnly = document.getElementById("fields-notes-only");
  const elCredNotes = document.getElementById("cred-notes");
  
  const elGenOutput = document.getElementById("gen-output");
  const elBtnGenRefresh = document.getElementById("btn-gen-refresh");
  const elBtnGenCopy = document.getElementById("btn-gen-copy");
  const elGenStrengthBadge = document.getElementById("gen-strength-badge");
  const elGenEntropyFill = document.getElementById("gen-entropy-fill");
  const elGenEntropyDesc = document.getElementById("gen-entropy-desc");
  const elGenLength = document.getElementById("gen-length");
  const elGenLengthVal = document.getElementById("gen-length-val");
  const elGenOptLower = document.getElementById("gen-opt-lower");
  const elGenOptUpper = document.getElementById("gen-opt-upper");
  const elGenOptNum = document.getElementById("gen-opt-num");
  const elGenOptSym = document.getElementById("gen-opt-sym");
  
  const elBtnReAudit = document.getElementById("btn-re-audit");
  const elAuditStatTotal = document.getElementById("audit-stat-total");
  const elAuditStatCompromised = document.getElementById("audit-stat-compromised");
  const elAuditStatWeak = document.getElementById("audit-stat-weak");
  const elAuditStatReused = document.getElementById("audit-stat-reused");
  const elAuditBadge = document.getElementById("audit-badge");
  const elAuditVulnerabilitiesList = document.getElementById("audit-vulnerabilities-list");
  const elAuditRecommendations = document.getElementById("audit-recommendations");
  
  const elVizPlaintextInput = document.getElementById("viz-plaintext-input");
  const elBtnRunViz = document.getElementById("btn-run-viz");
  const elVizMasterPw = document.getElementById("viz-master-pw");
  const elVizSalt = document.getElementById("viz-salt");
  const elVizDerivedKey = document.getElementById("viz-derived-key");
  const elVizPlaintextVal = document.getElementById("viz-plaintext-val");
  const elVizPlaintextHex = document.getElementById("viz-plaintext-hex");
  const elVizIvHex = document.getElementById("viz-iv-hex");
  const elVizCiphertextHex = document.getElementById("viz-ciphertext-hex");
  const elVizCiphertextBase64 = document.getElementById("viz-ciphertext-base64");
  
  const elSettingAutolockDuration = document.getElementById("setting-autolock-duration");
  const elBtnExportVault = document.getElementById("btn-export-vault");
  const elImportVaultFile = document.getElementById("import-vault-file");
  const elBtnDestroyVaultSettings = document.getElementById("btn-destroy-vault-settings");
  const elToastContainer = document.getElementById("toast-container");

  // --- App State variables ---
  let selectedItem = null;
  let activeCategoryFilter = "all";
  let autoLockTimeoutDuration = 5 * 60; // default 5 minutes in seconds
  let autoLockTimerId = null;
  let timeRemaining = autoLockTimeoutDuration;
  let clipboardClearTimerId = null;

  // ==========================================================================
  // INITIALIZATION
  // ==========================================================================
  async function init() {
    await setupAuthViews();
    setupNavigation();
    setupEventListeners();
    setupInactivityTracking();
    
    // Initial generator password render
    updateGeneratorPassword();
  }

  /**
   * Evaluates if database holds user accounts and renders UI accordingly.
   */
  async function setupAuthViews() {
    const databaseExists = await VaultManager.vaultExists();
    if (databaseExists) {
      elAuthLoginFlow.classList.remove("hidden");
      elAuthSetupFlow.classList.add("hidden");
      elLoginPassword.value = "";
      elLoginUsername.value = "";
      elLoginUsername.focus();
    } else {
      elAuthSetupFlow.classList.remove("hidden");
      elAuthLoginFlow.classList.add("hidden");
      elSetupUsername.value = "";
      elSetupPassword.value = "";
      elSetupPasswordConfirm.value = "";
      elSetupUsername.focus();
    }
    elAuthOverlay.classList.remove("hidden");
    elAppContainer.classList.add("hidden");
  }

  // ==========================================================================
  // TOAST NOTIFICATIONS
  // ==========================================================================
  function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span>${message}</span>
      <button class="toast-close">&times;</button>
    `;
    
    toast.querySelector(".toast-close").addEventListener("click", () => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    });

    elToastContainer.appendChild(toast);
    
    // Auto remove toast after 4 seconds
    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
      }
    }, 4000);
  }

  // ==========================================================================
  // NAVIGATION & TAB MANAGEMENT
  // ==========================================================================
  function setupNavigation() {
    elNavItems.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetViewId = btn.getAttribute("data-target");
        
        // Update active tab buttons
        elNavItems.forEach(i => i.classList.remove("active"));
        btn.classList.add("active");
        
        // Update active view panels
        elViews.forEach(view => {
          if (view.id === targetViewId) {
            view.classList.add("active");
          } else {
            view.classList.remove("active");
          }
        });

        // Trigger view-specific refreshes
        if (targetViewId === "view-vault") {
          renderVault();
        } else if (targetViewId === "view-audit") {
          runSecurityScan();
        } else if (targetViewId === "view-visualizer") {
          runCryptoVisualization();
        }
      });
    });
  }

  // ==========================================================================
  // EVENT LISTENERS HANDLERS
  // ==========================================================================
  function setupEventListeners() {
    
    // --- Setup Vault Form ---
    elSetupPassword.addEventListener("input", () => {
      const entropy = CryptoEngine.calculateEntropy(elSetupPassword.value);
      const rating = CryptoEngine.getEntropyStrength(entropy);
      elSetupPwStrength.querySelector(".strength-bar").style.width = `${Math.min(100, entropy * 0.8)}%`;
      elSetupPwStrength.querySelector(".strength-bar").style.backgroundColor = rating.color;
      elSetupPwStrength.querySelector(".strength-label").innerText = `Entropy: ${entropy} bits (${rating.label})`;
    });

    elSetupForm.addEventListener("submit", async () => {
      const username = elSetupUsername.value.trim();
      const pw = elSetupPassword.value;
      const pwConfirm = elSetupPasswordConfirm.value;
      
      if (!username) {
        showToast("Username is required.", "danger");
        return;
      }

      if (pw !== pwConfirm) {
        showToast("Passwords do not match.", "danger");
        return;
      }
      
      if (CryptoEngine.calculateEntropy(pw) < 35) {
        showToast("For safety, please choose a stronger Master Password.", "danger");
        return;
      }
      
      try {
        showToast("Hashing passwords and registering account... Please wait.", "info");
        const success = await VaultManager.createVault(username, pw);
        if (success) {
          showToast(`Welcome, ${username}! Vault successfully initialized.`, "success");
          unlockUIState();
        } else {
          showToast("Failed to complete automatic login.", "danger");
        }
      } catch (err) {
        console.error(err);
        showToast(err.message || "Failed to initialize vault.", "danger");
      }
    });

    // --- Unlock Form ---
    elLoginForm.addEventListener("submit", async () => {
      const username = elLoginUsername.value.trim();
      const pw = elLoginPassword.value;
      
      if (!username) {
        showToast("Username is required.", "danger");
        return;
      }

      try {
        const success = await VaultManager.unlock(username, pw);
        if (success) {
          showToast(`Access granted. Welcome back, ${username}!`, "success");
          unlockUIState();
        } else {
          showToast("Incorrect username or Master Password.", "danger");
          elLoginPassword.classList.add("shake-animation");
          setTimeout(() => elLoginPassword.classList.remove("shake-animation"), 500);
          elLoginPassword.value = "";
          elLoginPassword.focus();
        }
      } catch (err) {
        console.error(err);
        showToast("Connection or authentication error.", "danger");
      }
    });

    // --- Reset Server Database Warning on Lockscreen ---
    elBtnResetVaultWarning.addEventListener("click", () => {
      if (confirm("WARNING: You are about to wipe your local browser login session and reset the database structure.\n\nAre you sure?")) {
        VaultManager.destroyVault();
        showToast("Session cleared.", "info");
        setupAuthViews();
      }
    });

    // --- Manual Lock Action ---
    elBtnLockVaultAction.addEventListener("click", () => {
      lockVaultUI();
      showToast("Vault locked securely.", "info");
    });

    // --- Vault Filtering and Searching ---
    elVaultSearch.addEventListener("input", renderVault);
    
    elFilterBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        elFilterBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeCategoryFilter = btn.getAttribute("data-category");
        renderVault();
      });
    });

    // --- Add Credential Modal Open/Close ---
    elBtnAddCredentialModal.addEventListener("click", () => {
      openCredentialModal(null); // Null indicates a new item creation
    });
    
    const closeModal = () => elCredentialModal.classList.add("hidden");
    elBtnCloseModal.addEventListener("click", closeModal);
    elBtnCancelModal.addEventListener("click", closeModal);

    // --- Add Credential Modal Type Toggle ---
    elCredCategory.addEventListener("change", () => {
      const cat = elCredCategory.value;
      if (cat === "notes") {
        elFieldsLoginOnly.classList.add("hidden");
        elFieldsNotesOnly.classList.remove("hidden");
        elCredNotes.required = true;
      } else {
        elFieldsLoginOnly.classList.remove("hidden");
        elFieldsNotesOnly.classList.add("hidden");
        elCredNotes.required = false;
      }
    });

    // --- Password Visibility inside Modal ---
    elBtnCredPwShow.addEventListener("click", () => {
      if (elCredPassword.type === "password") {
        elCredPassword.type = "text";
        elBtnCredPwShow.querySelector("svg").style.fill = "var(--accent-cyan)";
      } else {
        elCredPassword.type = "password";
        elBtnCredPwShow.querySelector("svg").style.fill = "var(--text-muted)";
      }
    });

    // --- Inline Password Generator inside Modal ---
    elBtnCredPwGenerate.addEventListener("click", () => {
      const generated = CryptoEngine.generatePassword(18, { uppercase: true, lowercase: true, numbers: true, symbols: true });
      elCredPassword.value = generated;
      elCredPassword.type = "text";
      elBtnCredPwShow.querySelector("svg").style.fill = "var(--accent-cyan)";
      triggerCredPwStrengthCheck();
      showToast("Generated high-entropy password.", "info");
    });

    elCredPassword.addEventListener("input", triggerCredPwStrengthCheck);

    // --- Save Credential ---
    elCredentialForm.addEventListener("submit", async () => {
      const id = elCredId.value;
      const category = elCredCategory.value;
      
      const details = {
        title: elCredTitle.value,
        username: elCredUsername.value,
        password: elCredPassword.value,
        website: elCredWebsite.value,
        notes: elCredNotes.value
      };

      try {
        if (id) {
          // Edit operation
          await VaultManager.updateItem(id, category, details);
          showToast("Credential updated.", "success");
        } else {
          // Create operation
          await VaultManager.addItem(category, details);
          showToast("Credential encrypted and saved on server.", "success");
        }
        closeModal();
        renderVault();
        runSecurityScan(); // Trigger background sync
      } catch (err) {
        console.error(err);
        showToast("Failed to save credential to backend database.", "danger");
      }
    });

    // --- Password Generator Slider & Logic ---
    elGenLength.addEventListener("input", () => {
      elGenLengthVal.innerText = elGenLength.value;
      updateGeneratorPassword();
    });
    
    [elGenOptLower, elGenOptUpper, elGenOptNum, elGenOptSym].forEach(chk => {
      chk.addEventListener("change", updateGeneratorPassword);
    });

    elBtnGenRefresh.addEventListener("click", updateGeneratorPassword);
    
    elBtnGenCopy.addEventListener("click", () => {
      copyTextToClipboard(elGenOutput.value, "Generated password copied to clipboard!");
    });

    // --- Audit trigger ---
    elBtnReAudit.addEventListener("click", () => {
      runSecurityScan(true);
    });

    // --- Visualizer Run Step ---
    elBtnRunViz.addEventListener("click", runCryptoVisualization);

    // --- Settings handlers ---
    elSettingAutolockDuration.addEventListener("change", () => {
      autoLockTimeoutDuration = parseInt(elSettingAutolockDuration.value) * 60;
      localStorage.setItem("sec_vault_autolock", autoLockTimeoutDuration.toString());
      resetAutoLockTimer();
      showToast(`Auto-lock timeout updated to ${elSettingAutolockDuration.value} mins.`, "success");
    });

    elBtnExportVault.addEventListener("click", exportEncryptedVaultFile);
    
    elImportVaultFile.addEventListener("change", importEncryptedVaultFile);

    elBtnDestroyVaultSettings.addEventListener("click", () => {
      if (confirm("WARNING: This destroys your session token and logs you out of the server vault.\n\nConfirm logout?")) {
        VaultManager.destroyVault();
        showToast("Session logged out.", "danger");
        setupAuthViews();
      }
    });
  }

  // ==========================================================================
  // VAULT UNLOCK & LOCK UI STATES
  // ==========================================================================
  function unlockUIState() {
    elAuthOverlay.classList.add("hidden");
    elAppContainer.classList.remove("hidden");
    
    // Display logged-in user in sidebar status badge
    const badgeText = document.querySelector(".security-status-badge span:last-child");
    if (badgeText) {
      badgeText.innerText = `User: ${VaultManager.username}`;
    }

    // Load custom autolock duration
    const savedTimeout = localStorage.getItem("sec_vault_autolock");
    if (savedTimeout) {
      autoLockTimeoutDuration = parseInt(savedTimeout);
      elSettingAutolockDuration.value = (autoLockTimeoutDuration / 60).toString();
    }

    resetAutoLockTimer();
    renderVault();
    runSecurityScan();
  }

  function lockVaultUI() {
    VaultManager.lock();
    clearInterval(autoLockTimerId);
    
    // Reset badge
    const badgeText = document.querySelector(".security-status-badge span:last-child");
    if (badgeText) {
      badgeText.innerText = "Zero-Knowledge Active";
    }

    // Clear display elements
    elVaultList.innerHTML = "";
    elDetailContent.classList.add("hidden");
    elVaultDetailPanel.querySelector(".detail-empty-message").classList.remove("hidden");
    
    // Clear visualizer values
    elVizDerivedKey.innerText = "Locked - Unlock vault to inspect key";
    elVizSalt.innerText = "Locked";
    
    // Return to auth overlay
    setupAuthViews();
  }

  // ==========================================================================
  // INACTIVITY AUTO-LOCK TRACKER
  // ==========================================================================
  function setupInactivityTracking() {
    // Reset timer on user activity
    const activityEvents = ["mousemove", "mousedown", "keypress", "click", "scroll", "touchstart"];
    activityEvents.forEach(evtName => {
      document.addEventListener(evtName, () => {
        if (VaultManager.isUnlocked) {
          resetAutoLockTimer();
        }
      });
    });
  }

  function resetAutoLockTimer() {
    timeRemaining = autoLockTimeoutDuration;
    updateTimerDisplay();
    
    clearInterval(autoLockTimerId);
    autoLockTimerId = setInterval(() => {
      timeRemaining--;
      updateTimerDisplay();
      
      if (timeRemaining <= 0) {
        lockVaultUI();
        showToast("Vault auto-locked due to inactivity.", "warning");
      }
    }, 1000);
  }

  function updateTimerDisplay() {
    const mins = Math.floor(timeRemaining / 60).toString().padStart(2, "0");
    const secs = (timeRemaining % 60).toString().padStart(2, "0");
    elAutolockTimer.innerText = `${mins}:${secs}`;
  }

  // ==========================================================================
  // CREDENTIAL MODAL LOGIC
  // ==========================================================================
  function openCredentialModal(item = null) {
    elCredentialForm.reset();
    elCredPwStrength.classList.add("hidden");
    elCredPassword.type = "password";
    elBtnCredPwShow.querySelector("svg").style.fill = "var(--text-muted)";
    
    if (item) {
      // Edit Mode
      elModalTitle.innerText = "Edit Credential";
      elCredId.value = item.id;
      elCredCategory.value = item.category;
      elCredTitle.value = item.title;
      elCredUsername.value = item.username || "";
      elCredPassword.value = item.password || "";
      elCredWebsite.value = item.website || "";
      elCredNotes.value = item.notes || "";
      
      // Update Fields Visibility
      elCredCategory.dispatchEvent(new Event("change"));
      if (item.category !== "notes" && item.password) {
        triggerCredPwStrengthCheck();
      }
    } else {
      // Add Mode
      elModalTitle.innerText = "Add New Credential";
      elCredId.value = "";
      elCredCategory.value = "logins";
      elFieldsLoginOnly.classList.remove("hidden");
      elFieldsNotesOnly.classList.add("hidden");
      elCredNotes.required = false;
    }
    
    elCredentialModal.classList.remove("hidden");
    elCredTitle.focus();
  }

  function triggerCredPwStrengthCheck() {
    const pw = elCredPassword.value;
    if (!pw) {
      elCredPwStrength.classList.add("hidden");
      return;
    }
    elCredPwStrength.classList.remove("hidden");
    const entropy = CryptoEngine.calculateEntropy(pw);
    const rating = CryptoEngine.getEntropyStrength(entropy);
    elCredPwStrength.querySelector(".strength-bar").style.width = `${Math.min(100, entropy * 0.8)}%`;
    elCredPwStrength.querySelector(".strength-bar").style.backgroundColor = rating.color;
    elCredPwStrength.querySelector(".strength-label").innerText = `Entropy: ${entropy} bits (${rating.label})`;
  }

  // ==========================================================================
  // VAULT RENDERING
  // ==========================================================================
  async function renderVault() {
    if (!VaultManager.isUnlocked) return;
    
    try {
      const items = await VaultManager.getItems();
      const searchQuery = elVaultSearch.value.toLowerCase().trim();
      
      // Filter list
      const filtered = items.filter(item => {
        const matchesCategory = (activeCategoryFilter === "all" || item.category === activeCategoryFilter);
        const matchesSearch = !searchQuery || 
          (item.title && item.title.toLowerCase().includes(searchQuery)) ||
          (item.username && item.username.toLowerCase().includes(searchQuery)) ||
          (item.website && item.website.toLowerCase().includes(searchQuery));
        
        return matchesCategory && matchesSearch;
      });

      // Render Empty State if no results
      if (filtered.length === 0) {
        elVaultList.classList.add("hidden");
        elVaultEmptyState.classList.remove("hidden");
      } else {
        elVaultEmptyState.classList.add("hidden");
        elVaultList.classList.remove("hidden");
        
        elVaultList.innerHTML = "";
        filtered.forEach(item => {
          const itemEl = document.createElement("div");
          itemEl.className = `vault-item ${selectedItem && selectedItem.id === item.id ? "selected" : ""}`;
          
          let svgPath = "";
          let subtitle = "";
          
          if (item.category === "logins") {
            svgPath = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/>`;
            subtitle = item.username || item.website || "No username";
          } else if (item.category === "notes") {
            svgPath = `<path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/>`;
            subtitle = "Encrypted Text Note";
          } else if (item.category === "cards") {
            svgPath = `<path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/>`;
            subtitle = item.username ? `•••• •••• •••• ${item.username.slice(-4)}` : "Payment Card";
          }

          itemEl.innerHTML = `
            <div class="item-info">
              <div class="category-avatar">
                <svg viewBox="0 0 24 24">${svgPath}</svg>
              </div>
              <div class="item-meta">
                <span class="item-title">${escapeHtml(item.title)}</span>
                <span class="item-subtitle">${escapeHtml(subtitle)}</span>
              </div>
            </div>
            <div class="item-actions">
              <svg viewBox="0 0 24 24" class="svg-icon-sm text-dimmed"><path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z"/></svg>
            </div>
          `;

          itemEl.addEventListener("click", () => {
            selectedItem = item;
            // Update selection visuals
            document.querySelectorAll(".vault-item").forEach(el => el.classList.remove("selected"));
            itemEl.classList.add("selected");
            renderDetailPanel(item);
          });

          elVaultList.appendChild(itemEl);
        });
      }
    } catch (err) {
      console.error(err);
      showToast("Decryption error loading database items.", "danger");
    }
  }

  // ==========================================================================
  // DETAIL PANEL RENDERER
  // ==========================================================================
  function renderDetailPanel(item) {
    elDetailContent.innerHTML = "";
    
    let svgPath = "";
    if (item.category === "logins") svgPath = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/>`;
    else if (item.category === "notes") svgPath = `<path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/>`;
    else if (item.category === "cards") svgPath = `<path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/>`;

    let htmlFields = "";

    if (item.category === "logins" || item.category === "cards") {
      const usernameLabel = item.category === "cards" ? "Cardholder Name / Number" : "Username / Email";
      const pwLabel = item.category === "cards" ? "CVV / PIN" : "Password";
      
      htmlFields += `
        <div class="detail-field-box">
          <div class="field-header">
            <span>${usernameLabel}</span>
          </div>
          <div class="field-val-container">
            <span class="field-val font-fira select-all" id="det-user-val">${escapeHtml(item.username || "N/A")}</span>
            <div class="field-actions">
              <button class="icon-btn-inline btn-copy" data-target="det-user-val" title="Copy">
                <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
              </button>
            </div>
          </div>
        </div>

        <div class="detail-field-box">
          <div class="field-header">
            <span>${pwLabel}</span>
          </div>
          <div class="field-val-container">
            <span class="field-val masked select-all" id="det-pw-val" data-raw="${escapeHtml(item.password)}">••••••••••••</span>
            <div class="field-actions">
              <button class="icon-btn-inline btn-pw-toggle" data-target="det-pw-val" title="Reveal">
                <svg viewBox="0 0 24 24"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
              </button>
              <button class="icon-btn-inline btn-copy" data-target="det-pw-val" data-is-pw="true" title="Copy Securely">
                <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
              </button>
            </div>
          </div>
        </div>
      `;

      if (item.category === "logins" && item.website) {
        htmlFields += `
          <div class="detail-field-box">
            <div class="field-header">
              <span>Website</span>
            </div>
            <div class="field-val-container">
              <span class="field-val select-all" id="det-web-val">${escapeHtml(item.website)}</span>
              <div class="field-actions">
                <button class="icon-btn-inline btn-copy" data-target="det-web-val" title="Copy URL">
                  <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                </button>
                <a href="${item.website}" target="_blank" class="icon-btn-inline" title="Launch Website">
                  <svg viewBox="0 0 24 24" style="fill: var(--text-muted);"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41 9.83-9.83V10h2V3h-7z"/></svg>
                </a>
              </div>
            </div>
          </div>
        `;
      }
    } else if (item.category === "notes") {
      htmlFields += `
        <div class="detail-field-box">
          <div class="field-header">
            <span>Secure Cryptographic Note</span>
          </div>
          <div class="field-val-container">
            <span class="field-val fira-style select-all" id="det-notes-val">${escapeHtml(item.notes)}</span>
          </div>
          <div style="display:flex; justify-content:flex-end; margin-top: 0.5rem;">
            <button class="icon-btn-inline btn-copy" data-target="det-notes-val" title="Copy Note text">
              <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
              <span style="font-size:0.75rem; margin-left: 0.25rem;">Copy Note</span>
            </button>
          </div>
        </div>
      `;
    }

    elDetailContent.innerHTML = `
      <div class="detail-header">
        <div class="detail-avatar-flex">
          <div class="detail-avatar">
            <svg viewBox="0 0 24 24">${svgPath}</svg>
          </div>
          <div class="detail-main-info">
            <h3>${escapeHtml(item.title)}</h3>
            <span>${escapeHtml(item.category)}</span>
          </div>
        </div>
      </div>

      <!-- Auto clear notification bar -->
      <div id="clip-clear-notify" class="clipboard-progress hidden">
        <svg viewBox="0 0 24 24" class="svg-icon-sm" style="fill:currentColor;"><path d="M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm2 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>
        <span style="flex:1;">Securing clipboard buffer...</span>
        <div class="clipboard-progress-bar">
          <div id="clip-progress-fill" class="clipboard-progress-fill"></div>
        </div>
      </div>

      <div class="detail-fields">
        ${htmlFields}
      </div>

      <div class="detail-footer-actions">
        <button class="btn btn-secondary btn-edit-item">
          <svg viewBox="0 0 24 24" class="btn-icon"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
          <span>Edit Details</span>
        </button>
        <button class="btn btn-danger btn-delete-item">
          <svg viewBox="0 0 24 24" class="btn-icon"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
          <span>Delete Entry</span>
        </button>
      </div>
    `;

    // Hook listeners inside Detail Content
    const elBtnEdit = elDetailContent.querySelector(".btn-edit-item");
    const elBtnDelete = elDetailContent.querySelector(".btn-delete-item");
    const elBtnCopies = elDetailContent.querySelectorAll(".btn-copy");
    const elBtnToggles = elDetailContent.querySelectorAll(".btn-pw-toggle");

    elBtnEdit.addEventListener("click", () => {
      openCredentialModal(item);
    });

    elBtnDelete.addEventListener("click", async () => {
      if (confirm(`Are you sure you want to delete the credential "${item.title}"?\nThis wipes it from the server database.`)) {
        try {
          await VaultManager.deleteItem(item.id);
          showToast("Credential deleted.", "info");
          selectedItem = null;
          renderVault();
          elDetailContent.classList.add("hidden");
          elVaultDetailPanel.querySelector(".detail-empty-message").classList.remove("hidden");
          runSecurityScan();
        } catch (e) {
          showToast("Failed to delete item from server.", "danger");
        }
      }
    });

    elBtnCopies.forEach(btn => {
      btn.addEventListener("click", () => {
        const fieldId = btn.getAttribute("data-target");
        const isPw = btn.getAttribute("data-is-pw") === "true";
        const elField = document.getElementById(fieldId);
        
        const copyText = isPw ? elField.getAttribute("data-raw") : elField.innerText;
        copyTextToClipboard(copyText, isPw ? "Password copied securely. Clears in 10s." : "Copied to clipboard!");
        
        if (isPw) {
          triggerClipboardAutoClearTimer();
        }
      });
    });

    elBtnToggles.forEach(btn => {
      btn.addEventListener("click", () => {
        const fieldId = btn.getAttribute("data-target");
        const elField = document.getElementById(fieldId);
        const raw = elField.getAttribute("data-raw");
        
        if (elField.innerText === "••••••••••••") {
          elField.innerText = raw;
          elField.classList.remove("masked");
          btn.querySelector("svg").style.fill = "var(--accent-cyan)";
        } else {
          elField.innerText = "••••••••••••";
          elField.classList.add("masked");
          btn.querySelector("svg").style.fill = "var(--text-muted)";
        }
      });
    });

    elVaultDetailPanel.querySelector(".detail-empty-message").classList.add("hidden");
    elDetailContent.classList.remove("hidden");
  }

  // --- Copy Helper ---
  function copyTextToClipboard(text, successMessage) {
    if (!navigator.clipboard) {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed"; 
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        showToast(successMessage, "success");
      } catch (err) {
        showToast("Copy failed.", "danger");
      }
      document.body.removeChild(textArea);
      return;
    }

    navigator.clipboard.writeText(text).then(() => {
      showToast(successMessage, "success");
    }).catch(err => {
      showToast("Copy blocked by browser security.", "danger");
    });
  }

  /**
   * Periodically clears clipboard buffer for security.
   */
  function triggerClipboardAutoClearTimer() {
    const elNotify = document.getElementById("clip-clear-notify");
    const elFill = document.getElementById("clip-progress-fill");
    
    if (!elNotify) return;
    
    elNotify.classList.remove("hidden");
    elFill.style.transition = "none";
    elFill.style.width = "100%";
    
    // Trigger browser layout flush
    elFill.offsetHeight;
    elFill.style.transition = "width 10s linear";
    elFill.style.width = "0%";
    
    clearTimeout(clipboardClearTimerId);
    clipboardClearTimerId = setTimeout(() => {
      navigator.clipboard.writeText("").then(() => {
        showToast("Security clipboard buffer cleared.", "info");
      }).catch(() => {});
      
      elNotify.classList.add("hidden");
    }, 10000);
  }

  // ==========================================================================
  // SECURE RANDOM GENERATOR SECTION
  // ==========================================================================
  function updateGeneratorPassword() {
    const len = parseInt(elGenLength.value);
    const opts = {
      lowercase: elGenOptLower.checked,
      uppercase: elGenOptUpper.checked,
      numbers: elGenOptNum.checked,
      symbols: elGenOptSym.checked
    };

    if (!opts.lowercase && !opts.uppercase && !opts.numbers && !opts.symbols) {
      elGenOutput.value = "[Select at least one set]";
      elGenStrengthBadge.className = "badge danger";
      elGenStrengthBadge.innerText = "0 bits";
      elGenEntropyFill.style.width = "0%";
      elGenEntropyFill.style.backgroundColor = "var(--state-danger)";
      elGenEntropyDesc.innerText = "No character sets selected.";
      return;
    }

    const password = CryptoEngine.generatePassword(len, opts);
    elGenOutput.value = password;

    const entropy = CryptoEngine.calculateEntropy(password);
    const rating = CryptoEngine.getEntropyStrength(entropy);

    elGenStrengthBadge.className = `badge`;
    elGenStrengthBadge.style.backgroundColor = rating.color;
    elGenStrengthBadge.style.color = "#000";
    elGenStrengthBadge.innerText = `${entropy} bits (${rating.label})`;

    elGenEntropyFill.style.width = `${Math.min(100, entropy * 0.8)}%`;
    elGenEntropyFill.style.backgroundColor = rating.color;

    let attackDesc = "";
    if (entropy < 35) {
      attackDesc = "Weak password. Can be brute-forced instantly (< 1 second) on a standard laptop.";
    } else if (entropy < 60) {
      attackDesc = "Moderate password. Dictionary attacks will crack this in several minutes to hours.";
    } else if (entropy < 80) {
      attackDesc = "Good strength. Will take roughly 50,000 years to crack using normal high-density GPU rigs.";
    } else if (entropy < 100) {
      attackDesc = "Excellent strength. Crucial protection. Requires 4.5 billion years of grid compute processing.";
    } else {
      attackDesc = "Maximum protection. Cryptographically uncrackable. Exceeds the lifespan of the known universe.";
    }
    elGenEntropyDesc.innerText = attackDesc;
  }

  // ==========================================================================
  // VAULT AUDITING PROCESS
  // ==========================================================================
  async function runSecurityScan(isManual = false) {
    if (!VaultManager.isUnlocked) return;

    try {
      const report = await VaultManager.performAudit();
      
      // Update Stat counts
      elAuditStatTotal.innerText = report.total;
      elAuditStatCompromised.innerText = report.compromised.length;
      elAuditStatWeak.innerText = report.veryWeak + report.weak;
      
      const reusedGroupsCount = Object.keys(report.reused).length;
      elAuditStatReused.innerText = reusedGroupsCount;

      // Update Audit badge in sidebar
      const totalVulnerable = report.compromised.length + report.veryWeak + report.weak + reusedGroupsCount;
      if (totalVulnerable > 0) {
        elAuditBadge.innerText = totalVulnerable;
        elAuditBadge.classList.remove("hidden");
      } else {
        elAuditBadge.classList.add("hidden");
      }

      // Render Vulnerability Feed list
      elAuditVulnerabilitiesList.innerHTML = "";
      
      if (totalVulnerable === 0) {
        elAuditVulnerabilitiesList.innerHTML = `
          <div class="empty-state" style="padding: 2rem;">
            <div class="empty-icon-box" style="border-color: var(--state-success);">
              <svg viewBox="0 0 24 24" style="fill: var(--state-success);"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
            </div>
            <h3>No Vulnerabilities Found</h3>
            <p>Your passwords match all current local criteria!</p>
          </div>
        `;
      } else {
        // Red alerts - Compromised
        report.compromised.forEach(item => {
          const itemEl = document.createElement("div");
          itemEl.className = "vuln-item danger";
          itemEl.innerHTML = `
            <div class="vuln-icon-box">
              <svg viewBox="0 0 24 24" class="vuln-icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            </div>
            <div class="vuln-content">
              <h4>Breached Password: ${escapeHtml(item.title)}</h4>
              <p class="vuln-desc">Password <code>"${escapeHtml(item.password)}"</code> is highly common and matches standard leak datasets. This credentials card must be replaced immediately.</p>
              <div class="vuln-meta">Username: ${escapeHtml(item.username || "N/A")}</div>
            </div>
          `;
          elAuditVulnerabilitiesList.appendChild(itemEl);
        });

        // Orange alerts - Reuses
        for (const [pw, accounts] of Object.entries(report.reused)) {
          const itemEl = document.createElement("div");
          itemEl.className = "vuln-item warning";
          itemEl.innerHTML = `
            <div class="vuln-icon-box">
              <svg viewBox="0 0 24 24" class="vuln-icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            </div>
            <div class="vuln-content">
              <h4>Password Reused Across Multiple Accounts</h4>
              <p class="vuln-desc">You are using the same password across the following accounts: <strong>${accounts.map(escapeHtml).join(", ")}</strong>.</p>
              <div class="vuln-meta">Identified pattern: Key Re-usage</div>
            </div>
          `;
          elAuditVulnerabilitiesList.appendChild(itemEl);
        }

        // Orange alerts - Low entropy
        const items = await VaultManager.getItems();
        for (const item of items) {
          if (item.category === "logins" && item.password) {
            const ent = CryptoEngine.calculateEntropy(item.password);
            if (ent < 35 && !report.compromised.some(c => c.id === item.id)) {
              const itemEl = document.createElement("div");
              itemEl.className = "vuln-item warning";
              itemEl.innerHTML = `
                <div class="vuln-icon-box">
                  <svg viewBox="0 0 24 24" class="vuln-icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                </div>
                <div class="vuln-content">
                  <h4>Weak Password: ${escapeHtml(item.title)}</h4>
                  <p class="vuln-desc">Password has extremely low entropy (<code>${ent} bits</code>). Highly vulnerable to basic cracking scripts.</p>
                  <div class="vuln-meta">Username: ${escapeHtml(item.username || "N/A")}</div>
                </div>
              `;
              elAuditVulnerabilitiesList.appendChild(itemEl);
            }
          }
        }
      }

      // Render advisory recommendation list
      elAuditRecommendations.innerHTML = "";
      report.recommendations.forEach(rec => {
        const recEl = document.createElement("div");
        recEl.className = `rec-box ${rec.type}`;
        
        let recIcon = "";
        if (rec.type === "danger") recIcon = `<svg viewBox="0 0 24 24" class="svg-icon-sm" style="fill:currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;
        else if (rec.type === "warning") recIcon = `<svg viewBox="0 0 24 24" class="svg-icon-sm" style="fill:currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;
        else if (rec.type === "success") recIcon = `<svg viewBox="0 0 24 24" class="svg-icon-sm" style="fill:currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg>`;

        recEl.innerHTML = `
          <h4 class="rec-title">
            ${recIcon}
            <span>${escapeHtml(rec.title)}</span>
          </h4>
          <p class="rec-desc">${escapeHtml(rec.desc)}</p>
        `;
        elAuditRecommendations.appendChild(recEl);
      });

      if (isManual) {
        showToast("Vault scan finished. Audit dashboard updated.", "success");
      }
    } catch (err) {
      console.error(err);
      showToast("Security scan failed.", "danger");
    }
  }

  // ==========================================================================
  // CRYPTOGRAPHIC PLAYGROUND VISUALIZATION
  // ==========================================================================
  async function runCryptoVisualization() {
    if (!VaultManager.isUnlocked) {
      showToast("Please unlock vault to access the crypto pipeline.", "warning");
      return;
    }

    try {
      const rawText = elVizPlaintextInput.value;
      let parsed = {};
      
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        parsed = { notes: rawText };
      }

      // Execute visualization through backend API
      const steps = await VaultManager.getEncryptionStepsForVisualizer(
        parsed.title || "Visualization Test",
        parsed.username || "alice",
        parsed.password || "Password123!",
        parsed.website || "",
        parsed.notes || rawText
      );

      if (!steps) return;

      // Update HTML hex visual fields dynamically from server response
      elVizMasterPw.innerText = steps.masterPasswordLength;
      elVizSalt.innerText = steps.saltHex;
      elVizDerivedKey.innerText = steps.derivedKeyHex;
      
      elVizPlaintextVal.innerText = steps.plaintext;
      elVizPlaintextHex.innerText = steps.plaintextBytes;
      elVizIvHex.innerText = steps.ivHex;
      elVizCiphertextHex.innerText = steps.ciphertextHex;
      elVizCiphertextBase64.innerText = steps.ciphertextBase64;

    } catch (err) {
      console.error(err);
      showToast("Failed to run pipeline step.", "danger");
    }
  }

  // ==========================================================================
  // PORTABILITY (EXPORT & IMPORT FILES)
  // ==========================================================================
  async function exportEncryptedVaultFile() {
    if (!VaultManager.isUnlocked) return;
    
    try {
      const items = await VaultManager.getItems();
      
      const payload = {
        app: "Aura Vault",
        version: "2.0",
        exportDate: new Date().toISOString(),
        username: VaultManager.username,
        credentials: items
      };

      const jsonStr = JSON.stringify(payload, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement("a");
      a.href = url;
      a.download = `aura-vault-backup-${VaultManager.username}-${new Date().toISOString().split("T")[0]}.json`;
      document.body.appendChild(a);
      a.click();
      
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }, 0);

      showToast("Vault backup exported successfully.", "success");
    } catch (err) {
      console.error(err);
      showToast("Export failed.", "danger");
    }
  }

  function importEncryptedVaultFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function(e) {
      try {
        const payload = JSON.parse(e.target.result);
        
        // Validate backup structure
        if (payload.app !== "Aura Vault" || !payload.credentials) {
          showToast("Invalid Aura Vault backup file.", "danger");
          return;
        }

        if (confirm(`Importing backup. This will upload ${payload.credentials.length} credentials to your active server vault. Continue?`)) {
          showToast("Importing credentials... Please wait.", "info");
          
          let count = 0;
          for (const item of payload.credentials) {
            try {
              await VaultManager.addItem(item.category, item);
              count++;
            } catch (err) {
              console.error(`Import failed for item: ${item.title}`, err);
            }
          }
          
          showToast(`Successfully imported ${count} credentials to server database.`, "success");
          renderVault();
          runSecurityScan();
        }
      } catch (err) {
        console.error(err);
        showToast("Failed to parse file.", "danger");
      }
    };
    reader.readAsText(file);
    event.target.value = "";
  }

  // ==========================================================================
  // ESCAPE HTML HELPER
  // ==========================================================================
  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // --- Run Init ---
  init();
});
