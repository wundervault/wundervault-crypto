/**
 * Wundervault Zero-Knowledge Persistent Secrets — Client-Side Crypto Library
 * Uses Web Crypto API for all cryptographic operations.
 *
 * Phase 1: Core crypto primitives for ZK persistent secrets
 */

/**
 * Vault state machine
 */
const VaultState = {
  NO_VAULT: 'NO_VAULT',    // No vault exists locally
  LOCKED: 'LOCKED',        // Vault exists, key derived but not decrypted
  UNLOCKING: 'UNLOCKING',  // In progress of unlocking
  UNLOCKED: 'UNLOCKED',   // Escrow key available, ready to use
  ERROR: 'ERROR',          // An error occurred
};

// ---------------------------------------------------------------------------
// Utility: Base64 encoding/decoding
// ---------------------------------------------------------------------------

/**
 * Convert a Uint8Array of bytes to a base64 string.
 * Uses a safe table-based encoder that handles all byte values (0-255) correctly.
 * NOTE: btoa(String.fromCharCode(...bytes)) corrupts bytes > 127 in some environments.
 * @param {Uint8Array} bytes
 * @returns {string} base64-encoded string
 */
function bytesToBase64(bytes) {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    result += CHARS[b0 >> 2];
    result += CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    result += i + 1 < bytes.length ? CHARS[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    result += i + 2 < bytes.length ? CHARS[b2 & 63] : '=';
  }
  return result;
}

/**
 * Convert a base64 string to a Uint8Array of bytes.
 * @param {string} b64
 * @returns {Uint8Array}
 */
function base64ToBytes(b64) {
  if (!b64 || typeof b64 !== 'string') {
    throw new Error('base64ToBytes: expected a non-empty string, got ' + JSON.stringify(b64));
  }
  try {
    // atob() only handles standard Base64 (A-Za-z0-9+/=). Replace URL-safe chars (-_→+/).
    const stdB64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(stdB64), c => c.charCodeAt(0));
  } catch (e) {
    throw new Error('base64ToBytes: invalid base64 string: ' + b64.substring(0, 20) + '...');
  }
}

// ---------------------------------------------------------------------------
// Escrow key generation
// ---------------------------------------------------------------------------

/**
 * Generate a new 32-byte random escrow key.
 * This is the master key used to derive all content keys.
 * @returns {Uint8Array} 32 random bytes
 */
async function generateEscrowKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ---------------------------------------------------------------------------
// Passphrase-based key derivation (PBKDF2)
// ---------------------------------------------------------------------------

/**
 * Derive an AES-256-GCM key from a user passphrase using PBKDF2-SHA256.
 * Uses 600,000 iterations for strong brute-force resistance.
 *
 * @param {string} passphrase - User's passphrase
 * @param {Uint8Array} saltB64 - Salt as Uint8Array (from base64-decoded user.escrow_salt)
 * @returns {Promise<CryptoKey>} AES-256-GCM CryptoKey for encrypt/decrypt
 */
async function deriveKeyFromPassphrase(passphrase, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// Escrow key encryption/decryption (protects escrow key with passphrase)
// ---------------------------------------------------------------------------

/**
 * Encrypt the escrow key using a passphrase-derived key (AES-GCM).
 * The escrow key is the master key; this step protects it with the user's passphrase.
 *
 * @param {Uint8Array} escrowKey - The 32-byte escrow key to encrypt
 * @param {CryptoKey} passphraseKey - AES-256-GCM key derived from passphrase
 * @returns {Promise<{ciphertext: string, nonce: string}>} Base64-encoded ciphertext and nonce
 */
async function encryptEscrowKey(escrowKey, passphraseKey) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    passphraseKey,
    escrowKey
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    nonce: bytesToBase64(nonce),
  };
}

/**
 * Decrypt the escrow key using a passphrase-derived key (AES-GCM).
 *
 * @param {string} ciphertextB64 - Base64-encoded ciphertext
 * @param {string} nonceB64 - Base64-encoded 12-byte nonce
 * @param {CryptoKey} passphraseKey - AES-256-GCM key derived from passphrase
 * @returns {Promise<Uint8Array>} The decrypted 32-byte escrow key
 */
async function decryptEscrowKey(ciphertextB64, nonceB64, passphraseKey) {
  const ciphertext = base64ToBytes(ciphertextB64);
  const nonce = base64ToBytes(nonceB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    passphraseKey,
    ciphertext
  );
  return new Uint8Array(plaintext);
}

/**
 * Decrypt the escrow key using a recovery code (PBKDF2 → AES-GCM).
 * Used during account recovery when the user provides a recovery code.
 *
 * @param {string} ciphertextB64 - Base64-encoded ciphertext
 * @param {string} nonceB64 - Base64-encoded 12-byte nonce
 * @param {string} code - The recovery code (plaintext)
 * @param {Uint8Array} salt - The salt used for PBKDF2 derivation
 * @returns {Promise<Uint8Array>} The decrypted 32-byte escrow key
 */
async function decryptEscrowKeyFromCode(ciphertextB64, nonceB64, code, salt) {
  const ciphertext = base64ToBytes(ciphertextB64);
  const nonce = base64ToBytes(nonceB64);
  // PBKDF2: 600k iterations, SHA-256, 32-byte output
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(code),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    derivedKey,
    ciphertext
  );
  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// HKDF key derivation (for content keys)
// ---------------------------------------------------------------------------

/**
 * HKDF-SHA256 — derive bits from an input key material.
 *
 * @param {Uint8Array} ikm - Input key material
 * @param {Uint8Array} salt - Salt (should be unique per content)
 * @param {string} info - Info string (application-specific context)
 * @param {number} [length=32] - Number of bytes to derive
 * @returns {Promise<Uint8Array>} Derived key bytes
 */
async function hkdf(ikm, salt, info, length = 32) {
  const key = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new TextEncoder().encode(info),
    },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

/**
 * Derive a content encryption key from the escrow key and a content-specific salt.
 * Each secret gets its own unique content key derived via HKDF.
 *
 * @param {Uint8Array} escrowKey - The 32-byte master escrow key
 * @param {Uint8Array} contentSalt - Unique salt for this secret content
 * @returns {Promise<CryptoKey>} AES-256-GCM CryptoKey for encrypting/decrypting content
 */
async function deriveContentKey(escrowKey, contentSalt) {
  const bits = await hkdf(escrowKey, contentSalt, 'wundervault-v1-secret', 32);
  return crypto.subtle.importKey(
    'raw',
    bits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// Secret content encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt secret content using AES-GCM with a content key.
 *
 * @param {string} plaintext - The secret content to encrypt (string)
 * @param {CryptoKey} contentKey - AES-256-GCM key derived from escrow key + content salt
 * @returns {Promise<{ciphertext: string, nonce: string}>} Base64-encoded ciphertext and nonce
 */
async function encryptSecretContent(plaintext, contentKey) {
  const encoder = new TextEncoder();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    contentKey,
    encoder.encode(plaintext)
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    nonce: bytesToBase64(nonce),
  };
}

/**
 * Decrypt secret content using AES-GCM with a content key.
 *
 * @param {string} ciphertextB64 - Base64-encoded ciphertext
 * @param {string} nonceB64 - Base64-encoded 12-byte nonce
 * @param {CryptoKey} contentKey - AES-256-GCM key derived from escrow key + content salt
 * @returns {Promise<string>} The decrypted plaintext string
 */
async function decryptSecretContent(ciphertextB64, nonceB64, contentKey) {
  const ciphertext = base64ToBytes(ciphertextB64);
  const nonce = base64ToBytes(nonceB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    contentKey,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

// ---------------------------------------------------------------------------
// Export public API
// ---------------------------------------------------------------------------
// Agent setup crypto (client-side key generation)
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random API key.
 * Format: wv_agent_<agent_id>|<32-char-random>
 * The agent_id is generated server-side; the suffix is 32 random bytes base64url.
 */
async function generateAgentApiKey(agentId) {
  const suffixBytes = crypto.getRandomValues(new Uint8Array(24));
  // URL-safe base64: + → -, / → _, strip padding
  const suffix = bytesToBase64(suffixBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return 'wv_agent_' + agentId + '|' + suffix;
}

/**
 * Generate a random encryption key (32 bytes, base64url encoded).
 * Used as: HMAC key for auth, content-key encryption key for vault secrets.
 */
function generateAgentEncryptionKey() {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  // URL-safe base64: + → -, / → _, strip padding
  return bytesToBase64(keyBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute HMAC-SHA256(encryptionKey, apiKey).
 * Returns raw bytes → base64 encoded.
 * This is what the server stores as api_key_hmac.
 */
async function hmacApiKey(encryptionKeyB64, apiKey) {
  const keyBytes = base64ToBytes(encryptionKeyB64);
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(apiKey));
  return bytesToBase64(new Uint8Array(signature));
}

/**
 * Encrypt the agent payload with the passphrase.
 * Returns: base64(nonce || ciphertext) — same format as other Wundervault blobs.
 *
 * Encrypted payload JSON: { api_key, api_key_hmac, encryption_key }
 *   - api_key: the Bearer token for API authentication
 *   - api_key_hmac: HMAC-SHA256(api_key, hmac_key) — for server-side auth verification
 *   - encryption_key: the master key for decrypting vault secret content
 *
 * Encryption key: PBKDF2(passphrase, salt="wv-agent-setup-v1", 100000 iterations) → AES-256-GCM key
 * Format: base64(AES-256-GCM(nonce, derivedKey, JSON payload))
 */
async function encryptAgentSetupPayload(passphrase, apiKey, apiKeyHmac, encryptionKey) {
  const saltEnc = new TextEncoder().encode('wv-agent-setup-v1');
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltEnc, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const payload = JSON.stringify({ api_key: apiKey, api_key_hmac: apiKeyHmac, encryption_key: encryptionKey });
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    derivedKey,
    new TextEncoder().encode(payload)
  );
  // Format: base64(nonce || ciphertext)
  const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ciphertext), nonce.length);
  return bytesToBase64(combined);
}

// ---------------------------------------------------------------------------
// Agent vault key crypto (ZK — server never sees plaintext vault keys or secrets)
// ---------------------------------------------------------------------------

/**
 * Generate a random 32-byte vault key for an agent.
 * This key is used to encrypt secrets sent to that agent's vault.
 * Two copies are stored server-side — one encrypted for the dashboard user,
 * one encrypted for the agent.
 * @returns {Uint8Array} 32 random bytes
 */
function generateVaultKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypt a vault key (or any 32-byte key) with a master key using AES-256-GCM.
 * Returns base64(nonce[12] || ciphertext) — the format the server stores.
 *
 * @param {Uint8Array} vaultKeyBytes   - The 32-byte vault key to encrypt
 * @param {Uint8Array} masterKeyBytes  - The 32-byte key to encrypt with (escrow_key or encryption_key)
 * @returns {Promise<string>} base64(nonce || ciphertext)
 */
async function encryptVaultKey(vaultKeyBytes, masterKeyBytes) {
  const key = await crypto.subtle.importKey(
    'raw', masterKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, vaultKeyBytes);
  const combined = new Uint8Array(12 + ct.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ct), 12);
  return bytesToBase64(combined);
}

/**
 * Decrypt a vault key blob (base64(nonce[12] || ciphertext)) with a master key.
 *
 * @param {string}     blobB64         - base64(nonce || ciphertext)
 * @param {Uint8Array} masterKeyBytes  - The 32-byte key to decrypt with
 * @returns {Promise<Uint8Array>} The decrypted 32-byte vault key
 */
async function decryptVaultKey(blobB64, masterKeyBytes) {
  const key = await crypto.subtle.importKey(
    'raw', masterKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );
  const blob = base64ToBytes(blobB64);
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
  return new Uint8Array(pt);
}

/**
 * Encrypt a plaintext string for storage in an agent's vault entry.
 * Uses AES-256-GCM with the agent's vault key.
 *
 * @param {string}     plaintext      - Secret content to encrypt
 * @param {Uint8Array} vaultKeyBytes  - Agent's 32-byte vault key
 * @returns {Promise<{encrypted_content: string, content_nonce: string}>}
 *   Both values are base64-encoded. encrypted_content is the ciphertext only (no nonce prefix).
 *   content_nonce is the 12-byte IV.
 */
async function encryptForAgentVault(plaintext, vaultKeyBytes) {
  const key = await crypto.subtle.importKey(
    'raw', vaultKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    encrypted_content: bytesToBase64(new Uint8Array(ct)),
    content_nonce: bytesToBase64(nonce),
  };
}

/**
 * Sign a directive string using PBKDF2-HMAC-SHA256 with the plaintext as the key material.
 * Salt is randomly generated and embedded in the output, making the signature self-contained.
 * Matches app/crypto.py:sign_directive().
 *
 * @param {string}     directive       - Policy text (e.g. DEFAULT_DIRECTIVE)
 * @param {Uint8Array} plaintextBytes  - The secret content bytes (used as PBKDF2 password)
 * @returns {Promise<string>} base64(salt[16] || sig[32])
 */
async function signDirective(directive, plaintextBytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // PBKDF2-HMAC-SHA256: password=plaintextBytes, salt=salt, iterations=600_000, dklen=32
  const key = await crypto.subtle.importKey(
    'raw', plaintextBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
    key, 256
  );
  const hmacKey = new Uint8Array(derivedBits);
  const hmacCryptoKey = await crypto.subtle.importKey(
    'raw', hmacKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC', hmacCryptoKey,
    new TextEncoder().encode(directive)
  );
  return bytesToBase64(new Uint8Array([...salt, ...new Uint8Array(sig)]));
}

/**
 * Verify a directive signature.
 * Extracts the embedded salt, re-derives the HMAC key from plaintext, and compares.
 *
 * @param {string}     directive        - Policy text
 * @param {string}     signatureB64     - base64(salt[16] || sig[32])
 * @param {Uint8Array} plaintextBytes   - The secret content bytes
 * @returns {Promise<boolean>} true if valid, false if invalid
 */
async function verifyDirective(directive, signatureB64, plaintextBytes) {
  try {
    const blob = base64ToBytes(signatureB64);
    const salt = blob.slice(0, 16);
    const storedSig = blob.slice(16);
    const key = await crypto.subtle.importKey(
      'raw', plaintextBytes,
      { name: 'PBKDF2' },
      false, ['deriveBits']
    );
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
      key, 256
    );
    const hmacKey = new Uint8Array(derivedBits);
    const hmacCryptoKey = await crypto.subtle.importKey(
      'raw', hmacKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
    const computedSig = await crypto.subtle.sign(
      'HMAC', hmacCryptoKey,
      new TextEncoder().encode(directive)
    );
    // Constant-time compare
    const a = new Uint8Array(storedSig);
    const b = new Uint8Array(computedSig);
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Full ZK: proof_key derivation (CIR-027)
// ---------------------------------------------------------------------------

/**
 * Import raw key bytes as an AES-256-GCM CryptoKey.
 * Converts 32-byte proof_key raw bytes into a CryptoKey for encrypt/decrypt.
 * @param {Uint8Array} rawKeyBytes - 32-byte raw key
 * @returns {Promise<CryptoKey>} AES-256-GCM CryptoKey
 */
async function importAesKey(rawKeyBytes) {
  return crypto.subtle.importKey(
    'raw',
    rawKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive proof_key from passphrase and salt using double-PBKDF2.
 * Step 1: PK = PBKDF2(passphrase, salt, 600k)
 * Step 2: proof_key = PBKDF2(PK, "wundervault_proof", 600k)
 * @param {string} passphrase - User's passphrase
 * @param {Uint8Array} saltBytes - Salt bytes (from escrow_salt)
 * @returns {Promise<Uint8Array>} 32-byte proof_key (raw bytes)
 */
async function deriveProofKey(passphrase, saltBytes) {
  const encoder = new TextEncoder();
  // Step 1: PK = PBKDF2(passphrase, salt, 600k) → raw bits
  const pkMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const pkBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 600_000, hash: 'SHA-256' },
    pkMaterial,
    256
  );
  const pkBytes = new Uint8Array(pkBits);
  // Step 2: proof_key = PBKDF2(PK, "wundervault_proof", 600k) → raw bits
  const proofMaterial = await crypto.subtle.importKey(
    'raw',
    pkBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const proofBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode('wundervault_proof'),
      iterations: 600_000,
      hash: 'SHA-256',
    },
    proofMaterial,
    256
  );
  return new Uint8Array(proofBits);
}

/**
 * Compute SHA-256 hash of proof_key bytes and return as base64 string.
 * This is what the server stores as users.proof_key_hash.
 * @param {Uint8Array} proofKeyBytes - The 32-byte proof_key
 * @returns {Promise<string>} base64-encoded SHA-256 hash
 */
async function hashProofKey(proofKeyBytes) {
  const hashBuf = await crypto.subtle.digest('SHA-256', proofKeyBytes);
  return bytesToBase64(new Uint8Array(hashBuf));
}

// -------------------------------------------------------------------------------
// 2SKD: Two-Secret Key Derivation (CIR-034)
// -------------------------------------------------------------------------------

/**
 * Generate a 16-byte random Account Secret and store in localStorage.
 * Called once at vault setup. Never sent to server.
 * @returns {Uint8Array} 16 random bytes
 */
function generateAccountSecret() {
  const secret = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem('wv_account_secret', bytesToBase64(secret));
  return secret;
}

/**
 * Read Account Secret from localStorage.
 * Returns null if not present (new device — need recovery code).
 * @returns {Uint8Array|null}
 */
function getAccountSecret() {
  const stored = localStorage.getItem('wv_account_secret');
  if (!stored) return null;
  try { return base64ToBytes(stored); } catch { return null; }
}

/**
 * Store Account Secret in localStorage (used after recovery code flow).
 * @param {Uint8Array} bytes
 */
function setAccountSecret(bytes) {
  localStorage.setItem('wv_account_secret', bytesToBase64(bytes));
}

/**
 * Derive auth_key and vault_enc_key using the 2SKD pipeline.
 * PBKDF2(passphrase, salt) → HKDF-Extract(account_secret) → two HKDF-Expand outputs.
 *
 * @param {string}     passphrase     - User's vault passphrase
 * @param {Uint8Array} saltBytes      - 16-byte random salt (from escrow_salt)
 * @param {Uint8Array} accountSecret  - 16-byte Account Secret (from localStorage)
 * @returns {Promise<{authKeyBytes: Uint8Array, vaultEncKeyBytes: Uint8Array}>}
 */
async function derive2SKDKeys(passphrase, saltBytes, accountSecret) {
  const enc = new TextEncoder();

  // Step 1: PBKDF2 → base_key (raw bits)
  const baseMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']
  );
  const baseBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 600_000 },
    baseMaterial, 256
  );

  // Step 2: HKDF using base_key as IKM, account_secret as salt.
  // Import twice — some browsers (Safari) reject reusing an HKDF key for multiple deriveBits calls.
  const hkdfKeyAuth = await crypto.subtle.importKey(
    'raw', baseBits, 'HKDF', false, ['deriveBits']
  );
  const hkdfKeyEnc = await crypto.subtle.importKey(
    'raw', baseBits, 'HKDF', false, ['deriveBits']
  );

  // Step 3a: HKDF-Expand → auth_key
  const authBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: accountSecret, info: enc.encode('wundervault-auth-v1') },
    hkdfKeyAuth, 256
  );

  // Step 3b: HKDF-Expand → vault_enc_key
  const encBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: accountSecret, info: enc.encode('wundervault-enc-v1') },
    hkdfKeyEnc, 256
  );

  return {
    authKeyBytes: new Uint8Array(authBits),
    vaultEncKeyBytes: new Uint8Array(encBits),
  };
}

/**
 * Compute SHA-256 of auth_key bytes and return as base64.
 * This is what the server stores as users.proof_key_hash.
 * @param {Uint8Array} authKeyBytes
 * @returns {Promise<string>} base64-encoded SHA-256 hash
 */
async function hashAuthKey(authKeyBytes) {
  const hashBuf = await crypto.subtle.digest('SHA-256', authKeyBytes);
  return bytesToBase64(new Uint8Array(hashBuf));
}

// -------------------------------------------------------------------------------
// CIP-023: one-time secret verifier
// -------------------------------------------------------------------------------

/**
 * Compute SHA-256 of content key bytes and return as base64 string.
 * This is the verifier stored server-side for one-time secrets (CIP-023 §5).
 * @param {Uint8Array} contentKeyBytes - The 32-byte raw content key
 * @returns {Promise<string>} base64-encoded SHA-256 hash
 */
async function computeVerifier(contentKeyBytes) {
  return bytesToBase64(new Uint8Array(
    await crypto.subtle.digest('SHA-256', contentKeyBytes)));
}

// -------------------------------------------------------------------------------

window.WundervaultCrypto = {
  // Constants
  VaultState,

  // Utilities
  bytesToBase64,
  base64ToBytes,

  // Escrow key lifecycle
  generateEscrowKey,
  deriveKeyFromPassphrase,
  encryptEscrowKey,
  decryptEscrowKey,
  decryptEscrowKeyFromCode,

  // Content key derivation
  hkdf,
  deriveContentKey,

  // Secret content encryption
  encryptSecretContent,
  decryptSecretContent,

  // Agent setup crypto (client-side key generation)
  generateAgentApiKey,
  generateAgentEncryptionKey,
  hmacApiKey,
  encryptAgentSetupPayload,

  // Agent vault ZK crypto
  generateVaultKey,
  encryptVaultKey,
  decryptVaultKey,
  encryptForAgentVault,
  signDirective,
  verifyDirective,

  // Full ZK (CIR-027)
  importAesKey,
  deriveProofKey,
  hashProofKey,

  // CIP-023: one-time secret verifier
  computeVerifier,

  // 2SKD (CIR-034)
  generateAccountSecret,
  getAccountSecret,
  setAccountSecret,
  derive2SKDKeys,
  hashAuthKey,
};
