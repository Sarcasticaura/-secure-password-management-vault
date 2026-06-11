# Aura Vault - Zero-Knowledge Secure Password Manager

Aura Vault is a client-side, zero-knowledge secure password management system designed as a high-fidelity cybersecurity demonstration project. It runs entirely in the browser using the native **Web Crypto API**, ensuring that all cryptographic operations happen locally and that no plaintext keys or passwords ever leave the device.

---

## 🔒 Security Architecture & Controls

Aura Vault implements modern industry-standard cryptographic pipelines to protect user vaults:

1. **Key Derivation (PBKDF2-HMAC-SHA256)**:
   - Derives a 256-bit symmetric encryption key from the Master Password.
   - Utilizes **100,000 iterations** of PBKDF2 to increase the CPU/GPU workload for brute-forcing, defending against dictionary attacks.
   - Generates a unique **16-byte random salt** using `crypto.getRandomValues()` to prevent precomputed rainbow table attacks.
2. **Authenticated Symmetric Encryption (AES-256-GCM)**:
   - Uses Advanced Encryption Standard in Galois/Counter Mode with 256-bit keys to encrypt credentials.
   - GCM provides **authenticated encryption**, generating a cryptographic authentication tag that guarantees the confidentiality and integrity of vault payloads.
   - A unique **12-byte Initialization Vector (IV)** is generated for every credential card, ensuring identical entries result in completely different ciphertexts.
3. **Master Password Verification**:
   - Instead of storing a hash of the Master Password, Aura Vault encrypts a static verifier string (`"Vault Verified!"`) on setup.
   - Unlocking attempts to decrypt this string. Success validates the password; decryption failure indicates an incorrect password.
4. **Auto-Lock Tracker & Memory Security**:
   - Monitored inactivity locks the vault after 5 minutes (adjustable in settings).
   - Once locked, the derived key is instantly wiped from JavaScript memory variables, ensuring cold storage security.
5. **Clipboard Buffer Clearing**:
   - Copying a password triggers a 10-second countdown. Upon completion, the clipboard is programmatically cleared to prevent unauthorized exposure.

---

## 📁 Project Structure

```text
secure-password-manager/
├── index.html        # App layout (Dashboard, Auditor, Generator, Visualizer)
├── style.css         # "Cyber-Vault" responsive theme (Glassmorphism, Neon tones)
├── js/
│   ├── crypto.js     # Web Crypto API engine wrapper (PBKDF2, AES-GCM)
│   ├── vault.js      # Vault state manager (Persistence & Audits)
│   └── app.js        # UI controller & Interactive flow visualizer
└── README.md         # Project documentation (this file)
```

---

## 🚀 Getting Started

Since Aura Vault utilizes native browser capabilities, it requires no server-side compilation or external node dependencies:

1. Locate the project folder at:
   `C:\Users\ushub\.gemini\antigravity\scratch\secure-password-manager`
2. **Double-click `index.html`** to open it directly in any modern web browser (Chrome, Edge, Firefox, Safari).
3. Alternatively, serve the folder locally using a web server of your choice:
   - If Python is installed:
     ```bash
     python -m http.server 8000
     ```
     Then navigate to `http://localhost:8000` in your browser.

---

## 🛠️ Verification & Demonstration

Use these tabs in the application to demonstrate security principles:

- **Key Generator**: Toggle length and pools to see bits of entropy recalculate in real-time, displaying estimated crack difficulties.
- **Vault Audit**: Scanning shows a breakdown of weak passwords, reused passwords, and compromised leak simulations (checked locally against common wordlists).
- **Cryptographic Visualizer**: Input any test text and press **"Run Cryptographic Step"** to view a step-by-step hex and base64 dump of the key derivation and AES-GCM authentication pipelines.
- **Inspect Local Storage**: Press `F12` to open developer tools, go to **Application** -> **Local Storage**. You will see that the credentials array (`sec_vault_items`) is stored as fully encrypted base64 ciphertexts, unreadable without the master password.

---

## 🌐 Hosting on GitHub Pages

Since Aura Vault is built with static, client-side HTML, CSS, and JavaScript, it can be hosted for free on **GitHub Pages** in under a minute:

1. **Create a GitHub Repository**:
   - Go to GitHub and create a new public repository (e.g., `aura-vault`).
2. **Push the Files**:
   - Initialize git, commit all files (including `.gitignore`, `index.html`, `style.css`, and the `js/` folder), and push them to your repository:
     ```bash
     git init
     git add .
     git commit -m "Initial commit of Aura Vault"
     git branch -M main
     git remote add origin <your-github-repo-url>
     git push -u origin main
     ```
3. **Enable GitHub Pages**:
   - Go to your repository settings on GitHub.
   - Click on **Pages** in the left sidebar.
   - Under **Build and deployment** -> **Source**, select **Deploy from a branch**.
   - Under **Branch**, select `main` and `/ (root)`, then click **Save**.
4. **Access the Application**:
   - Within 1-2 minutes, GitHub will host the site at:
     `https://<your-username>.github.io/aura-vault/`
