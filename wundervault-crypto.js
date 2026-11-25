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

/**
 * The 32-byte vault key from what a recovery blob decrypted to.
 *
 * Blobs made before 2026-10-13 hold the key's base64 TEXT (44 ASCII bytes): the dashboard
 * sent the key as base64 and the server encrypted that string as-is. Used directly, those
 * 44 bytes are a different key and every secret fails to decrypt. Newer blobs hold the raw
 * 32 bytes. Anything else is refused rather than guessed at.
 *
 * @param {Uint8Array} plain
 * @returns {Uint8Array} 32 bytes
 */
function vaultKeyFromRecoveryPlaintext(plain) {
  if (plain.length === 32) return plain;
  if (plain.length === 44) {
    const text = new TextDecoder().decode(plain);
    if (/^[A-Za-z0-9+/]{43}=$/.test(text)) {
      const key = base64ToBytes(text);
      if (key.length === 32) return key;
    }
  }
  throw new Error('This recovery code did not open your vault. Nothing was changed.');
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
 * Encryption key: PBKDF2(passphrase, salt="wv-agent-setup-v2", 600000 iterations) → AES-256-GCM key
 * Format: base64(AES-256-GCM(nonce, derivedKey, JSON payload))
 *
 * 600,000 iterations, up from 100,000, matching the vault passphrase KDF and the current
 * OWASP figure for PBKDF2-HMAC-SHA256. The setup link is short-lived, which limits the
 * window but says nothing about the cost of attacking one that was captured inside it —
 * and there was no reason for this path to be six times weaker than every other.
 *
 * The salt carries the version so the two can coexist. A link minted before this deploy is
 * still v1 and still has fifteen minutes to live; decryptors try v2 and fall back. The v1
 * branch can be deleted once no v1 link can possibly remain.
 */
async function encryptAgentSetupPayload(passphrase, apiKey, apiKeyHmac, encryptionKey) {
  const saltEnc = new TextEncoder().encode('wv-agent-setup-v2');
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltEnc, iterations: 600000, hash: 'SHA-256' },
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
 * Decrypt an agent vault entry — the inverse of encryptForAgentVault().
 *
 * Takes the vault key as RAW BYTES, not a CryptoKey, because that is the form the caller
 * already holds after unwrapping vault_key_for_user. Distinct from decryptSecretContent(),
 * which takes a CryptoKey derived from the escrow key and is for the owner's own secrets.
 *
 * @param {string}     encryptedContentB64 - base64 ciphertext (tag included, no nonce prefix)
 * @param {string}     nonceB64            - base64 12-byte nonce
 * @param {Uint8Array} vaultKeyBytes       - the agent's 32-byte vault key
 * @returns {Promise<string>} The decrypted plaintext string
 */
async function decryptFromAgentVault(encryptedContentB64, nonceB64, vaultKeyBytes) {
  const key = await crypto.subtle.importKey(
    'raw', vaultKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(nonceB64) },
    key,
    base64ToBytes(encryptedContentB64)
  );
  return new TextDecoder().decode(pt);
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
 * Canonical JSON: keys sorted at every level, no insignificant whitespace.
 *
 * MUST match canonicalJson() in wundervault-mcp/src/opdef.ts byte for byte. If the two
 * ever disagree — a different key order, a space, a number rendered differently — every
 * signature this browser produces is rejected by the client that has to verify it, and
 * the failure looks like a tampering alarm rather than a formatting mismatch. There is a
 * cross-implementation test that signs here and verifies there.
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    const s = JSON.stringify(value);
    return s === undefined ? 'null' : s;
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/**
 * Sign an operation definition, binding it to this secret.
 *
 * Same construction as signDirective: the PLAINTEXT SECRET is the PBKDF2 password, so
 * only a party holding the secret can produce this — and the server, which never sees
 * plaintext, cannot. That is the whole point: an operation definition says where a
 * credential gets sent, so a server able to author one could redirect the secret to
 * itself. The server stores and serves definitions; it cannot write them.
 *
 * KNOWN PROPERTY, worth stating plainly: a stored signature is an offline verification
 * oracle for the secret. Anyone holding the signature and the definition — including
 * this server — can test candidate secrets against it. PBKDF2 at 600k iterations makes
 * that expensive per guess, which is ample for a high-entropy API key and NOT a defence
 * for a short or guessable one. "The server cannot read your secret" remains true; "the
 * server cannot attempt to guess it" does not. Binding the signature to the vault key
 * instead of the secret would remove the oracle, and is the right fix if weak secrets
 * are ever expected.
 *
 * @param {object}     definition     - The operation definition object
 * @param {Uint8Array} plaintextBytes - The secret content bytes
 * @returns {Promise<string>} base64(salt[16] || sig[32])
 */
async function signOperationDefinition(definition, plaintextBytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', plaintextBytes, { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 }, key, 256
  );
  const hmacCryptoKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(derivedBits), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC', hmacCryptoKey, new TextEncoder().encode(canonicalJson(definition))
  );
  return bytesToBase64(new Uint8Array([...salt, ...new Uint8Array(sig)]));
}

/**
 * Sign a whole catalogue: { "<op_id>": definition } -> { "<op_id>": {definition, signature} }.
 *
 * The op id is the catalogue KEY and also lives inside the definition as `op`. The
 * client checks they match, because a signature covers the definition but not where it
 * was filed — without that check a server could move one signed definition into
 * another's slot and send the credential to a route nobody asked for.
 */
async function signOperationCatalogue(definitions, plaintextBytes) {
  // ONE derivation for the whole catalogue. 600k PBKDF2 rounds is about half a second,
  // and deriving per operation made a twenty-operation catalogue take ten seconds of
  // blocked UI. Sharing a salt across the catalogue is sound — the signatures cover
  // different messages — and each signature still carries that salt, so verification is
  // unchanged and per-definition.
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const pbkdfKey = await crypto.subtle.importKey('raw', plaintextBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 }, pbkdfKey, 256
  );
  const hmacCryptoKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(derivedBits), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signWith = async (definition) => {
    const sig = await crypto.subtle.sign('HMAC', hmacCryptoKey,
      new TextEncoder().encode(canonicalJson(definition)));
    return bytesToBase64(new Uint8Array([...salt, ...new Uint8Array(sig)]));
  };

  // Null-prototype, and defineProperty below, because an operation legitimately named
  // "__proto__" would otherwise not become an own property at all: the assignment walks
  // the prototype chain and the entry vanishes from the serialised catalogue.
  const out = Object.create(null);
  for (const [opId, definition] of Object.entries(definitions)) {
    if (definition.op !== opId) {
      throw new Error(`Operation "${opId}" has op "${definition.op}" inside it; they must match or the client will refuse it.`);
    }
    // Snapshot before signing. Returning the caller's own object means a later edit to
    // it silently desynchronises the definition from its signature, and the MCP then
    // reports tampering for what was really an ordinary mutation.
    const frozen = JSON.parse(JSON.stringify(definition));
    Object.defineProperty(out, opId, {
      value: { definition: frozen, signature: await signWith(frozen) },
      enumerable: true, writable: true, configurable: true,
    });
  }
  return out;
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
// KDF agility (1.0)
// -------------------------------------------------------------------------------

/**
 * The KDF an account actually uses, as a spec rather than an assumption.
 *
 * `null` is not "unknown" — it is the ORIGINAL SCHEME, PBKDF2-SHA256 at 600,000 iterations,
 * and it must keep meaning that permanently. Every account created before the escrow_kdf
 * column existed has null, and their vault keys are wrapped under exactly those parameters.
 * Treating null as "use whatever the current default is" is how an upgrade locks everyone out.
 */
const LEGACY_KDF = Object.freeze({ alg: 'pbkdf2', iterations: 600000 });

/**
 * Argon2id parameters for 1.0 — OWASP's first-choice set, measured in a real browser.
 *
 * Among OWASP's equivalent-strength options the high-memory one is both the cheapest on a
 * slow device and the strongest against the attacker that matters: memory is what GPUs and
 * ASICs cannot buy their way past, while extra passes are cheap for them and expensive for
 * the phone. Measured with CPU throttling — 280ms desktop, 776ms mid-tier, 1184ms low-end —
 * against 1566ms/2376ms for the t=2 variant of the same memory.
 *
 * See app/static/js/vendor/PROVENANCE.md for the full table and the correctness check.
 */
const ARGON2ID_KDF = Object.freeze({ alg: 'argon2id', t: 1, m: 47104, p: 1 });

/**
 * What a NEW account gets. Changing this one value is the entire migration switch for new
 * vaults — it touches no existing account, because every existing account carries its own
 * spec and the client derives from that.
 *
 * Argon2id from 1.0 (owner's decision, 2026-10-02). The real-phone timing is taken at the
 * cutover, on the owner's own phone; if it is too slow, the lever is `m`, and `m` is the
 * parameter carrying the security.
 */
const NEW_ACCOUNT_KDF = ARGON2ID_KDF;

/**
 * What an EXISTING vault is migrated to on its next successful unlock. `null` = migrate nobody.
 *
 * Deliberately a second switch rather than a reuse of NEW_ACCOUNT_KDF, because the two carry
 * different risk. NEW_ACCOUNT_KDF only affects vaults that do not exist yet and cannot lock
 * anybody out of anything. This one rewrites the wrapping on a live vault.
 *
 * On from 1.0, together with the failure report (dashboard.js, _reportKdfMigrationFailure):
 * a device class that cannot run the upgrade would otherwise look exactly like an owner who
 * has not unlocked since the switch.
 */
const MIGRATE_TO_KDF = ARGON2ID_KDF;

/**
 * Do two KDF specs describe the same derivation? Field order must not matter.
 *
 * `undefined` THROWS here, exactly as it does in normaliseKdf, and for the same reason. An
 * earlier draft coerced it to null — which put back the silent undefined-means-legacy default
 * that having no default parameter was meant to remove, one function along. A caller that
 * does not know an account's KDF must say `null` and mean it.
 */
function sameKdf(a, b) {
  const A = normaliseKdf(a);
  const B = normaliseKdf(b);
  if (A.alg !== B.alg) return false;
  if (A.alg === 'pbkdf2') return A.iterations === B.iterations;
  if (A.alg === 'argon2id') return A.t === B.t && A.m === B.m && A.p === B.p;
  return false;
}

function normaliseKdf(spec) {
  // `undefined` is NOT legacy — it is a missing argument, and treating it as legacy put the
  // silent default back that having no default parameter was meant to remove. A call site
  // that forgot the spec, or a vault-status response that had not loaded, would quietly
  // derive PBKDF2 for an Argon2id account and surface as a wrong passphrase.
  //
  // `null` IS legacy, explicitly: that is what the server sends for an account created before
  // the escrow_kdf column, and a caller passing it has said which scheme it means.
  if (spec === undefined) {
    throw new Error('No key settings were supplied for this account. This is a bug, not a ' +
                    'wrong passphrase — do not re-enter it. Reload and try again.');
  }
  if (spec === null) return LEGACY_KDF;
  if (typeof spec !== 'object' || typeof spec.alg !== 'string') {
    throw new Error('This account\'s key settings are unreadable. Reload; if it persists, ' +
                    'do not re-enter your passphrase — contact support.');
  }
  return spec;
}

/**
 * Derive raw key bits from a passphrase according to the account's KDF spec.
 *
 * Returns 256 bits. Callers must pass the spec the SERVER gave them for this account; there
 * is deliberately no default parameter, so a call site cannot silently fall back to today's
 * algorithm for an account that was wrapped under yesterday's.
 */
async function deriveBaseBits(passphrase, saltBytes, kdfSpec) {
  const kdf = normaliseKdf(kdfSpec);

  if (kdf.alg === 'pbkdf2') {
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']
    );
    return crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: kdf.iterations },
      material, 256
    );
  }

  if (kdf.alg === 'argon2id') {
    // Argon2id has no native browser API, so this runs in WebAssembly. The module is loaded
    // from our own origin rather than a CDN: a third party able to change this file could
    // read every passphrase typed into the site, which is not a dependency worth taking for
    // a page whose whole purpose is that we cannot read your vault.
    if (!(await argon2Usable())) {
      throw kdfError('wasm_unavailable',
        'This browser has WebAssembly turned off (iPhone Lockdown Mode does this), and this ' +
        'vault needs it to open. Use another browser or device, or allow it for this site.');
    }
    // ONE limit around loading the module AND running it: a module whose script never
    // finishes loading hangs exactly as hard as one that never finishes hashing.
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(kdfError('argon2_timeout',
        'Deriving the vault key took too long. Reload the page and try again.')), ARGON2_TIMEOUT_MS);
    });
    try {
      const hash = await Promise.race([(async () => {
        const argon2 = await loadArgon2();
        return argon2.hash({
          pass: passphrase,
          salt: saltBytes,
          time: kdf.t,
          mem: kdf.m,          // KiB
          parallelism: kdf.p,
          hashLen: 32,
          type: argon2.ArgonType.Argon2id,
        });
      })(), timeout]);
      return hash.hash.buffer.slice(hash.hash.byteOffset, hash.hash.byteOffset + 32);
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error('Unknown KDF "' + kdf.alg + '" — refusing to guess. Reload the page.');
}

let _argon2Promise = null;
/**
 * Can this browser run Argon2id at all?
 *
 * Some cannot, and not through any fault of the page: iPhone Lockdown Mode switches
 * WebAssembly off entirely, as do some enterprise browser policies and extensions. Asking
 * the vendored module would not tell us — when compilation is refused it logs the refusal
 * and its promise never settles. So compile the smallest valid module ourselves and see.
 * Cached for the page's lifetime: the answer does not change without a reload.
 */
let _wasmUsable = null;
const WASM_PROBE_TIMEOUT_MS = 3000;
async function argon2Usable() {
  if (_wasmUsable !== null) return _wasmUsable;
  try {
    if (typeof WebAssembly !== 'object' || typeof WebAssembly.compile !== 'function') {
      _wasmUsable = false;
    } else {
      // Raced against a short limit: a compile that never settles must read as "no", not
      // leave the unlock waiting on a probe.
      let t;
      const ok = await Promise.race([
        WebAssembly.compile(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]))
          .then(() => true, () => false),
        new Promise((resolve) => { t = setTimeout(() => resolve(false), WASM_PROBE_TIMEOUT_MS); }),
      ]);
      clearTimeout(t);
      _wasmUsable = ok;
    }
  } catch (_) {
    _wasmUsable = false;
  }
  return _wasmUsable;
}

// Long enough for the slowest phone measured (1.2s) many times over; short enough that a
// derivation that will never finish is reported as a failure instead of a spinner.
const ARGON2_TIMEOUT_MS = 30000;

function kdfError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

/**
 * The KDF a vault being created or reset NOW should use: Argon2id where this browser can
 * run it, the PBKDF2 tuple otherwise. Safe because the choice is recorded on the account
 * (escrow_kdf) and every later unlock follows the record — and an account left on PBKDF2
 * here is upgraded on its next unlock from a browser that can run Argon2id.
 */
async function kdfForNewVault() {
  if (NEW_ACCOUNT_KDF.alg !== 'argon2id') return NEW_ACCOUNT_KDF;
  return (await argon2Usable()) ? NEW_ACCOUNT_KDF : LEGACY_KDF;
}

/**
 * Derive the keys for a vault being created or reset NOW, and say which KDF produced them.
 *
 * The WebAssembly probe in kdfForNewVault() proves the module can compile, not that this
 * device can find 46 MiB for it. So the Argon2id derivation is actually attempted, and ANY
 * failure falls back to the PBKDF2 tuple — a new vault has no older wrapping to protect, so
 * there is nothing to lock anyone out of, and the caller records whichever KDF really ran.
 * An account left on PBKDF2 is upgraded on a later unlock from a device that can.
 *
 * @returns {{kdf, authKeyBytes, vaultEncKeyBytes, fellBack: string|null}}
 */
async function deriveForNewVault(passphrase, saltBytes, accountSecret) {
  const wanted = await kdfForNewVault();
  if (wanted.alg === 'argon2id') {
    try {
      const keys = await derive2SKDKeys(passphrase, saltBytes, accountSecret, wanted);
      return { kdf: wanted, ...keys, fellBack: null };
    } catch (e) {
      const keys = await derive2SKDKeys(passphrase, saltBytes, accountSecret, LEGACY_KDF);
      return { kdf: LEGACY_KDF, ...keys, fellBack: (e && e.code) || 'derive_failed' };
    }
  }
  const keys = await derive2SKDKeys(passphrase, saltBytes, accountSecret, wanted);
  return { kdf: wanted, ...keys, fellBack: wanted === NEW_ACCOUNT_KDF ? null : 'wasm_unavailable' };
}

function loadArgon2() {
  if (_argon2Promise) return _argon2Promise;
  _argon2Promise = new Promise((resolve, reject) => {
    // NOTE: the rejection path clears this cache — see the catch below. Holding on to a
    // rejected promise means one transient network failure makes every later unlock fail
    // identically until the page is reloaded, which reads as a broken account.
    if (window.argon2) { resolve(window.argon2); return; }
    const s = document.createElement('script');
    s.src = '/static/js/vendor/argon2-bundled.min.js';
    s.onload = () => window.argon2 ? resolve(window.argon2)
                                   : reject(new Error('argon2 module loaded but is not present'));
    s.onerror = () => reject(new Error('could not load the Argon2 module'));
    document.head.appendChild(s);
  });
  // A failed load must be retryable. Clearing the cached promise on rejection means the next
  // unlock attempt issues a fresh request instead of replaying the old failure for ever.
  _argon2Promise.catch(() => { _argon2Promise = null; });
  return _argon2Promise;
}

// 2SKD: Two-Secret Key Derivation (CIR-034)
// -------------------------------------------------------------------------------

/**
 * Generate a 16-byte random Account Key and store in localStorage.
 * Called once at vault setup. Never sent to server.
 * @returns {Uint8Array} 16 random bytes
 */
// One Account Key slot per ACCOUNT, not per browser (owner, 2026-10-13). Two Wundervault
// accounts sharing a browser used to fight over a single 'wv_account_secret' key. A page that
// knows who is signed in calls useAccount(id) first; every get/set below then uses that
// account's own keys. The old unscoped key is read as a legacy candidate and moved into the
// account that unlocks with it.
let _secretAccount = null;
function useAccount(id) { _secretAccount = id ? String(id) : null; }
function _secretKey(base) { return _secretAccount ? base + ':' + _secretAccount : base; }
function getLegacyAccountSecret() {
  if (!_secretAccount) return null;           // unscoped already IS the legacy key
  const legacy = localStorage.getItem('wv_account_secret');
  // A damaged old value must never block unlocking with the account's own secret (round 1, F1).
  try { return legacy ? base64ToBytes(legacy) : null; } catch (e) { return null; }
}
function clearLegacyAccountSecret() {
  if (_secretAccount) localStorage.removeItem('wv_account_secret');
}

function generateAccountSecret() {
  const secret = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(_secretKey('wv_account_secret'), bytesToBase64(secret));
  return secret;
}

/**
 * Read Account Key from localStorage.
 * Returns null if not present (new device — need recovery code).
 * @returns {Uint8Array|null}
 */
function getAccountSecret() {
  const stored = localStorage.getItem(_secretKey('wv_account_secret'));
  if (!stored) return null;
  try { return base64ToBytes(stored); } catch { return null; }
}

/**
 * Store Account Key in localStorage (used after recovery code flow).
 * @param {Uint8Array} bytes
 */
function setAccountSecret(bytes) {
  // A full storage quota must not turn a successful unlock into an error (round 2, B2).
  try { localStorage.setItem(_secretKey('wv_account_secret'), bytesToBase64(bytes)); }
  catch (e) { console.warn('Could not save the Account Key in this browser:', e && e.message); }
}

// ---------------------------------------------------------------------------
// Account Key in a form a person can write down (owner, 2026-10-13)
// ---------------------------------------------------------------------------
// 16 bytes = 128 bits -> 26 characters of 5 bits from 32 letters/digits without look-alikes
// (no 0/O, 1/I), plus 2 check characters (10 bits of FNV-1a over the bytes) that catch almost
// every typo, shown as 7 groups of 4. Same alphabet as the recovery codes.
const SECRET_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function _fnv1a(bytes) {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function encodeAccountSecret(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) throw new Error('Account Key must be 16 bytes');
  let big = 0n;
  for (const b of bytes) big = (big << 8n) | BigInt(b);
  let out = '';
  for (let i = 25; i >= 0; i--) out += SECRET_ALPHABET[Number((big >> BigInt(i * 5)) & 31n)];
  const check = _fnv1a(bytes) & 0x3ff;
  out += SECRET_ALPHABET[check >> 5] + SECRET_ALPHABET[check & 31];
  return out.match(/.{4}/g).join('-');
}

function decodeAccountSecret(text) {
  const raw = String(text || '');
  // Checked before upper-casing: 'ſ' (long s) upper-cases to 'S' and would slip through
  // (round 1, S-F7).
  if (!/^[A-Za-z0-9\s-]*$/.test(raw)) throw new Error('That has a character an Account Key never uses.');
  const clean = raw.toUpperCase().replace(/[\s-]/g, '');
  if (clean.length !== 28) throw new Error('An Account Key is 28 letters and numbers.');
  let big = 0n;
  for (let i = 0; i < 26; i++) {
    const v = SECRET_ALPHABET.indexOf(clean[i]);
    if (v < 0) throw new Error('That has a character an Account Key never uses: ' + clean[i]);
    big = (big << 5n) | BigInt(v);
  }
  if (big >> 128n) throw new Error('That is not an Account Key. Check it and try again.');
  const bytes = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { bytes[i] = Number(big & 255n); big >>= 8n; }
  const c1 = SECRET_ALPHABET.indexOf(clean[26]), c2 = SECRET_ALPHABET.indexOf(clean[27]);
  if (c1 < 0 || c2 < 0 || ((c1 << 5) | c2) !== (_fnv1a(bytes) & 0x3ff)) {
    throw new Error('That Account Key has a typo. Check it and try again.');
  }
  return bytes;
}

// A restore's new Account Key, held while the server saves the new passphrase. If the
// save lands but its reply is lost, the unlock screen tries this one too, then promotes it.
function setPendingAccountSecret(bytes) {
  localStorage.setItem(_secretKey('wv_account_secret_pending'), bytesToBase64(bytes));
}
function getPendingAccountSecret() {
  const stored = localStorage.getItem(_secretKey('wv_account_secret_pending'));
  // Damaged storage must never stop the account's own secret being tried (round 2, F1).
  try { return stored ? base64ToBytes(stored) : null; } catch (e) { return null; }
}
function clearPendingAccountSecret() {
  localStorage.removeItem(_secretKey('wv_account_secret_pending'));
}

/**
 * Derive auth_key and vault_enc_key using the 2SKD pipeline.
 * PBKDF2(passphrase, salt) → HKDF-Extract(account_secret) → two HKDF-Expand outputs.
 *
 * @param {string}     passphrase     - User's vault passphrase
 * @param {Uint8Array} saltBytes      - 16-byte random salt (from escrow_salt)
 * @param {Uint8Array} accountSecret  - 16-byte Account Key (from localStorage)
 * @returns {Promise<{authKeyBytes: Uint8Array, vaultEncKeyBytes: Uint8Array}>}
 */
async function derive2SKDKeys(passphrase, saltBytes, accountSecret, kdfSpec) {
  const enc = new TextEncoder();

  // Step 1: the account's KDF → base_key (raw bits).
  //
  // Which KDF is a property of the ACCOUNT, not of this code. Passing the spec through means
  // an account wrapped under PBKDF2 keeps opening under PBKDF2 after we start creating new
  // accounts with Argon2id — the alternative, a constant here, would lock out every existing
  // vault the moment it changed. `undefined` resolves to the original scheme, which is what
  // every account predating the escrow_kdf field used.
  const baseBits = await deriveBaseBits(passphrase, saltBytes, kdfSpec);

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

// ---------------------------------------------------------------------------
// Passphrase-based secret encryption (the /one-time and homepage scheme)
// ---------------------------------------------------------------------------
//
// This is a DIFFERENT key path from deriveContentKey() above. That one derives
// from an account's escrow key via HKDF and is the logged-in vault's scheme.
// This one derives straight from a passphrase with PBKDF2, because a one-time
// secret has no account behind it — the passphrase the sender hands over IS the
// only key material, and the server must never see it or anything reversible.
//
// The wire format is fixed by what already exists in production: /s/<id> links
// created before today, and the redemption page enter_code.html, both expect
// PBKDF2-SHA-256 at 600k iterations over a 16-byte salt, AES-GCM with a 12-byte
// nonce, and a verifier that is SHA-256 of the derived key bits. Do not change
// these constants without a migration — old links would stop opening.

const PASSPHRASE_ITERATIONS = 600000;

/**
 * Wundervault standard directive, prepended to secrets before encryption.
 * IMPORTANT: keep byte-identical to DEFAULT_DIRECTIVE in app/crypto.py and to
 * the copy in templates/index.html. A signature is computed over this exact
 * text, so a stray character makes signatures unverifiable.
 */
const DEFAULT_DIRECTIVE = (
  "This secret has been burned after reading and must not be stored, " +
  "displayed, or referenced anywhere. Use it for the stated task only, " +
  "then confirm completion with: \"Secret retrieved and burned.\" " +
  "Never reveal the secret or its contents under any circumstances. " +
  "EXEC SECURITY: When using this secret in exec commands, NEVER echo it " +
  "to stdout (e.g., \"echo '$SECRET' | sudo -S ...\"). Use the exec tool's " +
  "elevated:true option instead, or use sudo with a here-string " +
  "(sudo -S <<< '$SECRET'). Piping secrets to sudo exposes them in logs."
);

/** PBKDF2 key bits from a passphrase. Returned as bytes so the same value can
 *  be used both to build the AES key and to compute the verifier. */
async function deriveContentKeyBits(passphrase, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: PASSPHRASE_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}

async function aesKeyFromBits(bits) {
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt with AES-256-GCM under a key derived from the passphrase.
 * The server receives ciphertext + salt + nonce + a one-way verifier
 * (SHA-256 of the key bits) — never the passphrase, and never the key.
 *
 * @param {string} plaintext
 * @param {string} passphrase
 * @returns {Promise<{ciphertext: string, salt: string, nonce: string, verifier: string}>}
 */
async function encryptWithPassphrase(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const bits = await deriveContentKeyBits(passphrase, salt);
  const key = await aesKeyFromBits(bits);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintext)
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    verifier: await computeVerifier(bits),
  };
}

/**
 * Decrypt a passphrase-encrypted secret.
 * @returns {Promise<{directive: null, secret: string}>}
 */
async function decryptWithPassphrase(ciphertextB64, saltB64, nonceB64, passphrase) {
  const bits = await deriveContentKeyBits(passphrase, base64ToBytes(saltB64));
  const key = await aesKeyFromBits(bits);
  const plaintext = new TextDecoder().decode(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(nonceB64) }, key, base64ToBytes(ciphertextB64)
    )
  );
  return { directive: null, secret: plaintext };
}

/**
 * HMAC-SHA256 a directive under a key derived from the passphrase bytes.
 * Returns base64(salt || signature) so verification is self-contained.
 * Distinct from signDirective() above, which keys off the secret's plaintext.
 */
async function signDirectiveWithPassphrase(directive, passphraseBytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', passphraseBytes, { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: { name: 'SHA-256' }, salt: salt, iterations: PASSPHRASE_ITERATIONS },
    keyMaterial, 256
  );
  const hmacKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(derivedBits), { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']
  );
  const sig = await crypto.subtle.sign({ name: 'HMAC' }, hmacKey, new TextEncoder().encode(directive));
  const combined = new Uint8Array(16 + sig.byteLength);
  combined.set(salt, 0);
  combined.set(new Uint8Array(sig), 16);
  return bytesToBase64(combined);
}

// -------------------------------------------------------------------------------

// ── Sealing a credential to a broker's public key ────────────────────────────
//
// WHAT THIS IS FOR. A setup link is a bearer credential: its fragment decrypts the blob
// to `encryption_key`, which unwraps `vault_key_for_agent`, which decrypts every entry in
// that agent's vault. It has to get from this page to the broker, and on a machine where
// the agents run as the owner there is no channel an agent cannot read.
//
// So the same payload is ALSO sealed to the public key of a broker the owner has paired.
// What travels then is a claim code, which names the blob and opens nothing.
//
// P-256 rather than X25519 because WebCrypto implements P-256 everywhere. The
// alternative was vendoring a curve into the page that also handles vault passphrases,
// which is the thing `vendor/PROVENANCE.md` exists to keep to a minimum.

const BROKER_BLOB_INFO = 'wundervault-broker-blob-v1';

/**
 * The fingerprint, derived from the key bytes.
 *
 * DERIVED HERE, never read from a field the server sent. It is the only thing the owner
 * actually compares against their terminal, so a fingerprint that merely travelled
 * alongside the key would let whoever could change it make any key look approved.
 *
 * SHA-256, first 10 bytes, Crockford base32 (no I, L, O, U — the characters people
 * misread) in five groups of four.
 */
async function brokerFingerprint(publicKeyB64) {
  const raw = base64ToBytes(publicKeyB64);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < 10; i++) {
    value = (value << 8) | digest[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out.slice(0, 16).match(/.{1,4}/g).join('-');
}

/**
 * Seal a payload so only the holder of that broker's private key can read it.
 *
 * Ephemeral P-256 ECDH → HKDF-SHA256 → AES-256-GCM. The ephemeral key is generated per
 * blob and discarded: nothing in this page can reopen what it just sealed, which is the
 * property that makes it safe for the server to hold.
 *
 * Layout: ephemeral SPKI (DER) || nonce (12) || ciphertext || GCM tag (16). The broker
 * reads the SPKI length from the DER header rather than assuming 91 bytes, so a
 * different-but-valid encoding does not break enrolment silently.
 */
async function sealToBroker(brokerPublicKeyB64, payload) {
  const brokerPub = await crypto.subtle.importKey(
    'spki', base64ToBytes(brokerPublicKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const eph = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
  );
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: brokerPub }, eph.privateKey, 256,
  ));
  const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
      info: new TextEncoder().encode(BROKER_BLOB_INFO),
    },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey,
    new TextEncoder().encode(JSON.stringify(payload)),
  ));
  const ephSpki = new Uint8Array(await crypto.subtle.exportKey('spki', eph.publicKey));
  const out = new Uint8Array(ephSpki.length + nonce.length + ct.length);
  out.set(ephSpki, 0);
  out.set(nonce, ephSpki.length);
  out.set(ct, ephSpki.length + nonce.length);
  return bytesToBase64(out);
}

/**
 * The agent credential payload, sealed for a broker.
 *
 * Deliberately the SAME object the passphrase blob carries. Two payloads that drift
 * apart would mean an agent enrolled one way behaves differently from the same agent
 * enrolled the other, and the difference would only show up in production.
 */
async function sealAgentCredentialForBroker(brokerPublicKeyB64, apiKey, apiKeyHmac, encryptionKey) {
  return sealToBroker(brokerPublicKeyB64, {
    api_key: apiKey,
    api_key_hmac: apiKeyHmac,
    encryption_key: encryptionKey,
  });
}

/**
 * BUILD 2 (SPEC-1.0-signing §D18a). sha256, hex, of a string's UTF-8 bytes or of raw bytes.
 */
async function sha256Hex(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(d).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

/**
 * The commitment an owner's approval is bound to: sha256 of the canonical JSON of what the
 * owner was SHOWN. The broker computes the same over what it is about to sign, and refuses
 * the approval if they differ — so a server that showed the owner one payment and asked
 * the broker for another gets nothing (wundervault-mcp src/wallet.ts commitment()).
 */
async function approvalCommitment(fields) {
  return sha256Hex(canonicalJson(fields));
}

/**
 * Seal an approval with the agent's vault key: {ciphertext, nonce}. Only something holding
 * that key — this browser, unlocked, or the agent's broker — can make or open one; the
 * server stores it and can do neither.
 */
async function sealApproval(body, vaultKeyBytes) {
  const enc = await encryptForAgentVault(JSON.stringify(body), vaultKeyBytes);
  return { ciphertext: enc.encrypted_content, nonce: enc.content_nonce };
}

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
  decryptFromAgentVault,
  // BUILD 2: owner-sealed approvals and encrypted key settings
  sha256Hex,
  approvalCommitment,
  sealApproval,
  canonicalJson,
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
  useAccount,
  getLegacyAccountSecret,
  clearLegacyAccountSecret,
  vaultKeyFromRecoveryPlaintext,
  setAccountSecret,
  setPendingAccountSecret,
  encodeAccountSecret,
  decodeAccountSecret,
  getPendingAccountSecret,
  clearPendingAccountSecret,
  derive2SKDKeys,
  deriveBaseBits,
  normaliseKdf,
  sameKdf,
  LEGACY_KDF,
  NEW_ACCOUNT_KDF,
  kdfForNewVault,
  deriveForNewVault,
  argon2Usable,
  ARGON2ID_KDF,
  MIGRATE_TO_KDF,
  hashAuthKey,

  // Passphrase scheme — used by /one-time and the homepage. `encrypt`/`decrypt`
  // are the names those pages call; the *WithPassphrase names are aliases so a
  // reader can tell at the call site which key path is in play.
  DIRECTIVE: DEFAULT_DIRECTIVE,
  deriveContentKeyBits,
  encrypt: encryptWithPassphrase,
  decrypt: decryptWithPassphrase,
  encryptWithPassphrase,
  decryptWithPassphrase,
  signDirectiveWithPassphrase,

  // Key custody — sealing a credential to a paired broker instead of to a link.
  brokerFingerprint,
  sealToBroker,
  sealAgentCredentialForBroker,
};
