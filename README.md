# wundervault-crypto

The client-side, zero-knowledge cryptography library used by [Wundervault](https://wundervault.com).

This is the browser code that encrypts your secrets **before anything leaves your device**. It is published openly so you can verify the zero-knowledge claim for yourself: the Wundervault server only ever receives ciphertext, a salt, a nonce, and a one-way verifier — never your passphrase, your keys, or your plaintext.

It uses only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — no third-party crypto dependencies.

## What it does

- **AES-256-GCM** authenticated encryption/decryption of secret contents.
- **Key derivation** via PBKDF2-HMAC-SHA256 (600,000 iterations) and HKDF, with per-secret salts.
- **Escrow-key model** — a vault key is wrapped under a passphrase-derived key; the server stores only the wrapped blob.
- **Account Secret** generation/storage (kept in the browser, never sent).
- Safe base64 helpers that correctly handle all byte values.

The public surface is exposed as `window.WundervaultCrypto`.

## Why it's public

For a zero-knowledge product, trust comes from auditability. The proof that "the server can't read your secrets" lives in the *client* — this file — not the server. This code is already delivered to every visitor's browser as plaintext JavaScript; publishing it here just makes it easy to read, diff, and audit.

## Security model

See the full threat model and cryptographic design in the [Wundervault whitepaper](https://wundervault.com/whitepaper).

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`). See [LICENSE](LICENSE).

Wundervault is **open-core**: the client and MCP server are open source; the hosted service at [wundervault.com](https://wundervault.com) is a commercial offering.
