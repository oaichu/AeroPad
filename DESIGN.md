# DESIGN SPECIFICATION — AETHERPAD & 2FA VAULT

## 1. Visual Contract & Design Tokens
All UI and rendering must strictly consume tokens defined in `design/tokens-v1.json`.

* **Base Surface (Dark Mode - Default)**:
  - Canvas: `#07090E` (Deep Space Obsidian)
  - Surface Glass: `rgba(16, 22, 34, 0.75)` with `backdrop-filter: blur(28px) saturate(180%)`
  - Elevated Cards: `rgba(22, 30, 46, 0.90)`
* **Light Mode Surface**:
  - Canvas: `#F4F6FB` (Frost Titanium)
  - Surface Glass: `rgba(255, 255, 255, 0.82)`
* **Borders & Outlines**:
  - Hairline: `1px solid rgba(255, 255, 255, 0.08)` (Dark) / `rgba(0, 0, 0, 0.08)` (Light)
  - Active Glow: `rgba(0, 242, 254, 0.4)`
* **Accents & Semantics**:
  - `Electric Cyan`: `#00F2FE` (Primary branding, TOTP live digit highlight)
  - `Web3 Indigo`: `#6366F1` (Secondary badges, aura glow)
  - `Security Mint`: `#10B981` (Safe encryption state, passed checks)
  - `Expiry Amber`: `#F59E0B` (TOTP countdown < 5 seconds warning)
  - `Destructive Coral`: `#F43F5E` (Delete / Reset actions)

## 2. Typography
* **Prose, Navigation & Controls**: `-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Inter', sans-serif`
* **Digits, Secret Keys & Monospace Codes**: `'SF Mono', 'JetBrains Mono', 'Fira Code', monospace` with `font-variant-numeric: tabular-nums` to ensure stable rendering during countdowns.

## 3. Architecture & Interaction Model
* **Client-Side Principle**: Pure client-side execution; all cryptographic operations (TOTP RFC 6238 HMAC calculation, AES-256-GCM vault encryption, QR generation & decoding, secure random generation) take place strictly within the browser using Web Crypto API. No data ever leaves the device.
* **Encryption at Rest (optional, user-enabled)**: With a master password set, `aeropad_notes` and `aeropad_totp` are stored as `{"v":1,"enc":"AES-GCM-256","kdf":"PBKDF2-SHA256","iter":310000,"salt","iv","ct"}` envelopes. Key derivation: PBKDF2-SHA256, 310,000 iterations, 16-byte random salt (fresh per password set). The derived AES key is a non-extractable `CryptoKey` held only in memory and re-derived from the password at every boot (lock screen). Random 12-byte IV per write. **No recovery path** — a forgotten master password means the data is unrecoverable by design. Without a master password, data is stored in plain text.
* **Storage Keys**: LocalStorage key-value pairs (`aeropad_notes`, `aeropad_totp`, `aeropad_theme`, `aeropad_lang`; `*_corrupt_backup` after recovery from corrupted data).
* **Supply Chain**: CDN scripts (qrcode-generator, jsQR) are version-pinned with SRI hashes; a strict CSP (including the standalone's inline-script sha256) is shipped via `_headers` / `vercel.json`.
