# DESIGN SPECIFICATION — AeroPad Local-First Security Workbench

## 1. Product direction

AeroPad is a local-first 2FA and security workbench: no account, no backend, no telemetry, and encrypted vault content persisted in the browser. The commercial product language is:

> **AeroPad — Local-First 2FA & Security Workbench**
> Secrets stay in your browser. Encrypted by default. No account. No tracking.

The product must not claim “zero-knowledge”, “no data ever leaves the device”, “Apple-grade”, “Apple + Web3”, or “decentralized” as general security guarantees. The precise claim is that AeroPad does not upload vault content and that vault content is encrypted at rest by the client before persistence.

## 2. Visual contract

`design/tokens-v1.json` is the locked token source. `styles.css`, the security UX, and future preview/demo artifacts must consume those values rather than inventing new colors, fonts, radii, or spacing.

- Dark mode is the default; light mode remains supported.
- Prose and controls use the locked sans family; codes and secrets use the locked monospace family with tabular numerals.
- Cyan is the primary focus/live-code accent; mint means committed/encrypted; amber means pending/expiring; coral means destructive or failed.
- Motion must honor `prefers-reduced-motion`.

## 3. Security UX contract

- New vault data is encrypted by default. Plaintext mode is a legacy migration state, not a recommended product state.
- The UI must distinguish `locked`, `saving`, `committed`, `backup-ready`, and `save-failed` states. “Saved” is shown only after the durable commit succeeds.
- Secret inputs are masked by default and have explicit reveal controls. Passwords and TOTP seeds are cleared from transient DOM fields after use where practical.
- Locking awaits the storage queue flush before clearing the session key or reloading. A failed flush is visible and leaves the last committed generation intact.
- Security modals use dialog semantics, labelled controls, keyboard escape, focus return, and a focus trap while open.
- TOTP cards show their own period and algorithm. No global 30-second label may contradict an account’s configuration.

## 4. Technical references

- Vault storage and encrypted backup: [`specs/vault-schema.md`](specs/vault-schema.md)
- TOTP/otpauth behavior: [`specs/totp-otpauth.md`](specs/totp-otpauth.md)
- Remediation scope and release gates: [`specs/security-remediation.md`](specs/security-remediation.md)
- Runtime ownership and build flow: [`docs/architecture.md`](docs/architecture.md)

## 5. Privacy and distribution

- Runtime dependencies, fonts, and QR libraries are self-hosted and pinned in the build output.
- Production CSP uses `script-src 'self'` after vendor removal; `Referrer-Policy: no-referrer` and a restrictive `Permissions-Policy` are required.
- Static hosting remains the deployment model. No server API, user account, remote search, or telemetry is part of the vault runtime.
- `public/`, `dist/`, and the standalone HTML are generated artifacts. Source changes happen in the canonical source tree and are verified before artifacts are published.
