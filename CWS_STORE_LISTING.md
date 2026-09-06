# AeroPad - Chrome Web Store Store Listing

## Product Title
**AeroPad - 2FA Authenticator & Encrypted Notes**

## Summary / Short Description (Max 132 chars)
Local-first two-factor authenticator (TOTP) and AES-256 encrypted notes for every website with zero cloud telemetry.

## Category
**Productivity / Developer Tools**

## Language Support
- English (en), Vietnamese (vi), Spanish (es), Arabic (ar), Hindi (hi), Indonesian (id), Japanese (ja), Korean (ko), Portuguese (pt), Chinese (zh)

---

## Detailed Description (CWS Markdown)

**AeroPad** is an ultra-secure, local-first browser extension providing two-factor authentication (TOTP) and per-website encrypted note management directly in Chrome.

### 🛡️ Why AeroPad?
Most 2FA apps require third-party cloud sync or invasive mobile logins. AeroPad operates on a zero-knowledge, local-first architecture: all keys, TOTP secrets, and encrypted notes remain strictly stored in your local browser sandbox, encrypted with AES-256-GCM.

### 🌟 Key Features
- **Instant TOTP Codes**: Real-time two-factor authentication code generation supporting 6-digit & 8-digit codes, 30s & 60s periods, and SHA-1/SHA-256 algorithms.
- **Smart 2FA Autofill**: Automatically recognizes 2FA input fields on login pages and offers one-click autofill (or shortcut `Ctrl+Shift+F`).
- **Domain-Specific Encrypted Notes**: Store secret keys, backup recovery codes, and sensitive notes scoped to the active domain.
- **QR Code Scanner**: Scan 2FA QR codes right from your active tab without reaching for your phone.
- **Zero-Knowledge Encryption**: Master password derived using PBKDF2 with 600,000 iterations and AES-256-GCM encryption.
- **Configurable Auto-Lock**: Automatically lock vault after inactivity timeout (1 min to 60 mins).
- **Offline Backup & Restore**: Export encrypted backups or standard JSON format anytime.
- **100% Privacy Focused**: Zero telemetry, zero external network requests, zero third-party trackers.

### 🔒 Security Invariants
- No cloud account required.
- Keys are never transmitted over the network.
- Memory cleared on lock.

---

## Chrome Web Store Asset Checklist
- [x] Icon 16x16, 48x48, 128x128 (`dist/icons/`)
- [x] Small Promo Tile 440x280 (`store-assets/promo-small-440x280.png`)
- [x] Marquee Promo Tile 1400x560 (`store-assets/promo-marquee-1400x560.png`)
- [x] Screenshot 1280x800 (`store-assets/screenshot-1280x800.png`)
- [x] Privacy Policy Document (`PRIVACY.md`)
- [x] Permissions Justification (`PERMISSIONS_JUSTIFICATION.md`)
- [x] Production Zip Bundle (`aeropad-ext-v0.1.0-cws.zip`)
