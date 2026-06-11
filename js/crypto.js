/**
 * Cryptographic Utility Engine for Secure Password Manager
 * Handles client-side encryption, decryption, key derivation, and secure generation.
 */

const CryptoEngine = {
  // --- Buffer Conversion Utilities ---

  /**
   * Converts a string to an ArrayBuffer (UTF-8).
   */
  stringToBuffer(str) {
    return new TextEncoder().encode(str);
  },

  /**
   * Converts an ArrayBuffer to a string (UTF-8).
   */
  bufferToString(buffer) {
    return new TextDecoder().decode(buffer);
  },

  /**
   * Converts an ArrayBuffer to a Base64 string.
   */
  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Converts a Base64 string to an ArrayBuffer.
   */
  base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  /**
   * Converts an ArrayBuffer to a Hexadecimal string.
   */
  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  // --- Cryptographic Functions ---

  /**
   * Generates a random salt buffer of specified byte length.
   */
  generateSalt(bytes = 16) {
    const salt = new Uint8Array(bytes);
    window.crypto.getRandomValues(salt);
    return salt;
  },

  /**
   * Generates a random initialization vector (IV) buffer for AES-GCM (12 bytes is standard).
   */
  generateIV(bytes = 12) {
    const iv = new Uint8Array(bytes);
    window.crypto.getRandomValues(iv);
    return iv;
  },

  /**
   * Derives a cryptographic key from a Master Password using PBKDF2.
   * We set extractable: true so we can inspect the raw derived key in our educational visualizer.
   */
  async deriveKey(masterPassword, saltBuffer, iterations = 100000) {
    const passwordBuffer = this.stringToBuffer(masterPassword);
    
    // Import the raw password as a key-derivation key
    const baseKey = await window.crypto.subtle.importKey(
      "raw",
      passwordBuffer,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    
    // Derive a symmetric 256-bit AES-GCM key
    return await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: iterations,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      true, // extractable (true allows us to display it in the cryptographic visualizer)
      ["encrypt", "decrypt"]
    );
  },

  /**
   * Exports a CryptoKey to raw hex bytes for display purposes.
   */
  async exportKeyToHex(key) {
    try {
      const exported = await window.crypto.subtle.exportKey("raw", key);
      return this.bufferToHex(exported);
    } catch (e) {
      console.error("Failed to export key:", e);
      return "Unavailable";
    }
  },

  /**
   * Encrypts plaintext string using AES-GCM with a derived key.
   * Returns object containing base64 ciphertext and base64 iv.
   */
  async encrypt(plaintext, key, ivBuffer) {
    const plaintextBuffer = this.stringToBuffer(plaintext);
    
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: ivBuffer
      },
      key,
      plaintextBuffer
    );

    return {
      ciphertext: this.bufferToBase64(ciphertextBuffer),
      iv: this.bufferToBase64(ivBuffer.buffer || ivBuffer)
    };
  },

  /**
   * Decrypts ciphertext (base64) using AES-GCM with a derived key and iv (base64).
   * Returns plaintext string.
   */
  async decrypt(ciphertextBase64, key, ivBase64) {
    const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
    const ivBuffer = this.base64ToBuffer(ivBase64);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBuffer
      },
      key,
      ciphertextBuffer
    );

    return this.bufferToString(decryptedBuffer);
  },

  // --- Password Utilities ---

  /**
   * Generates a secure random password using Web Crypto random values.
   */
  generatePassword(length = 16, options = { uppercase: true, lowercase: true, numbers: true, symbols: true }) {
    let charset = "";
    if (options.lowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (options.uppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (options.numbers) charset += "0123456789";
    if (options.symbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (charset.length === 0) return "";

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    
    let password = "";
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }
    return password;
  },

  /**
   * Measures password entropy in bits.
   * Entropy = L * log2(R) where L is length, R is pool size.
   */
  calculateEntropy(password) {
    if (!password) return 0;
    
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33; // Approx count of standard symbol chars
    
    if (poolSize === 0) return 0;
    
    const entropy = password.length * Math.log2(poolSize);
    return Math.round(entropy);
  },

  /**
   * Standardizes password strength rating based on entropy bits.
   */
  getEntropyStrength(entropy) {
    if (entropy < 35) return { score: 0, label: "Very Weak", color: "#ff4a4a" };
    if (entropy < 60) return { score: 1, label: "Weak", color: "#ff8c3a" };
    if (entropy < 80) return { score: 2, label: "Medium", color: "#ffd23a" };
    if (entropy < 100) return { score: 3, label: "Strong", color: "#3ad29f" };
    return { score: 4, label: "Excellent (Very Secure)", color: "#3aafff" };
  }
};

// Export for browser script usage
window.CryptoEngine = CryptoEngine;
