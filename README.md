# AeroPad — Local-First 2FA & Security Workbench

> Secrets stay in your browser. Encrypted by default. No account. No tracking.

AeroPad is a static browser application for TOTP accounts, QR import/generation, and private notes. **AeroPad does not upload vault content.** The runtime has no backend, account service, remote search, or telemetry.

## What it does

- **Encrypted vault:** notes, TOTP seeds, and account passwords are committed as one encrypted IndexedDB snapshot using AES-256-GCM. The current KDF baseline is PBKDF2-HMAC-SHA256 with 600,000 iterations.
- **Live TOTP:** RFC 6238 codes with strict SHA-1, SHA-256, and SHA-512 handling, supported 6/8 digit formats, and per-account periods.
- **QR studio:** generate and decode `otpauth://totp/` data with the account’s algorithm, digits, and period preserved.
- **Local notes:** Markdown editing, metrics, export, Unicode-aware local search, and no remote index.
- **Encrypted recovery:** export and restore a versioned `.aeropad` backup without offering a plaintext secret export.
- **Self-hosted runtime:** fonts and QR libraries are vendored for offline-friendly builds and a strict self-only CSP.

## Security boundary

Encryption protects vault bytes at rest and the master key is held only for the unlocked session. While the vault is unlocked, plaintext necessarily exists in browser memory and selected DOM controls so the application can render and edit it.

A compromised deployment, malicious future update, hostile same-origin JavaScript, or a browser extension may read plaintext while the vault is unlocked. CSP, self-hosted dependencies, strict parsing, short-lived secret fields, automatic locking, and artifact verification reduce risk but cannot remove that web-app boundary.

There is no master-password recovery. Browser storage can be cleared or evicted, so keep an encrypted `.aeropad` backup somewhere you control and periodically test restoring it. Persistent-storage requests are best-effort hints, not a guarantee against browser deletion.

## Run locally

```bash
npm ci
npm run verify
npm run build
```

`npm run verify` runs the unit suite, browser-level E2E checks, build, CSP/artifact parity, dependency checks, and claim-policy scan. Use `npm run claims:check` to check public product wording independently.

## Deployment

- Cloudflare Pages: build command `npm run build`, output directory `dist`.
- Vercel: run `npm run build`; the generated `public/` directory is the deployment artifact.
- Standalone file: `npm run build:standalone` generates `aeropad-standalone.html` from the canonical source files.

See [docs/SECURITY-AND-PRIVACY.md](docs/SECURITY-AND-PRIVACY.md) for the threat model, data categories, recovery limits, and privacy boundary. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for shipped asset licenses.
