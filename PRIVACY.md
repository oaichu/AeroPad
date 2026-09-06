# Privacy Policy for AeroPad

**Effective Date:** September 6, 2026
**Developer:** AeroPad Open Source Community

AeroPad is designed with a fundamental commitment to user privacy and data security. This Privacy Policy details how AeroPad handles user data in accordance with the Google Chrome Web Store User Data Policy.

## 1. Single Purpose
AeroPad serves a single, narrow purpose: providing local-first two-factor authentication (TOTP) and domain-specific encrypted notes for websites visited by the user.

## 2. Information Collection and Storage
- **Zero External Telemetry:** AeroPad does NOT collect, transmit, sell, or rent any personal identification information, browsing habits, IP addresses, or keystrokes to any remote servers.
- **Local-Only Storage:** All 2FA secrets, domain pairings, and notes are stored exclusively within the browser's local sandbox via `chrome.storage.local`.
- **Zero-Knowledge Cryptography:** Vault contents are encrypted client-side using AES-256-GCM with a key derived from the user's master password (PBKDF2, 600,000 iterations). Without the master password, data cannot be decrypted by anyone, including the extension developers.

## 3. Web Navigation & Content Scripts
AeroPad content scripts only inspect the DOM on the active webpage to detect standard 2FA input fields (`autocomplete="one-time-code"`, OTP fields) to facilitate autofill when requested by the user. Content scripts do not read or record user passwords or personal data.

## 4. Third-Party Disclosures
AeroPad contains no analytics SDKs, no advertisement trackers, and no third-party integrations.

## 5. Contact & Inquiries
For questions, vulnerability disclosures, or audits, open an issue on the project repository.
