# AeroPad Runtime Architecture

## System boundary

AeroPad is a static browser application. The runtime has no backend, API, account service, remote search, telemetry, or server-side decryption. The browser owns rendering, Web Crypto operations, QR processing, local search, and IndexedDB persistence.

The threat model protects vault content at rest from casual storage inspection and accidental corruption. It does not claim to protect plaintext from hostile same-origin JavaScript delivered by a compromised deployment, browser extension, or future malicious update. Deployment integrity and supply-chain controls therefore remain part of the security boundary.

## Canonical source ownership

The target source tree has one owner per responsibility:

```text
index.html                 canonical application shell and accessible markup
styles.css                 canonical visual implementation of design/tokens-v1.json
src/app.js                 browser controller and event wiring
src/crypto/base32.js       Base32 codec and secure secret generation
src/crypto/totp.js         RFC 6238 engine and per-period calculations
src/crypto/otpauth.js      strict OTPAuth URI builder/parser
src/crypto/vault-crypto.js envelope validation, KDF, AES-GCM, AAD, key lifecycle
src/storage/vault-store.js IndexedDB transaction queue, flush, backup record I/O
src/storage/legacy-migration.js one-time localStorage migration and recovery states
src/notes/notes-manager.js note model, metrics, export payloads, local search helpers
scripts/build.mjs          deterministic build, vendor copy, CSP hash, artifact checks
tests/                     unit and storage-contract tests against src modules
scripts/e2e-verify.mjs     browser-level acceptance against the built application
```

The existing root `app.js`, `public/`, `dist/`, and standalone HTML are transition artifacts. They are generated from the canonical tree and are not independent implementation surfaces. A build check must fail when generated artifacts differ from the source output.

## Runtime data flow

```text
user input
  → src/app.js validates intent and updates in-memory state
  → NotesManager / TOTP modules normalize domain data
  → VaultStore serializes one snapshot
  → VaultCrypto validates envelope inputs, derives non-extractable key,
    encrypts with AES-256-GCM and generation AAD
  → one IndexedDB readwrite transaction commits `vault/current`
  → UI reports committed state only after transaction completion
```

Unlocking reverses the flow: validate the stored envelope before KDF, derive the key from the supplied password, verify the AES-GCM tag and AAD, validate the decrypted payload, then initialize the UI. Any failure leaves the lock screen active and preserves the stored record.

## Build and deployment flow

The build uses a declared, pinned dev dependency to bundle `src/app.js` and its imports. It then produces a clean `dist/` directory containing `index.html`, `styles.css`, `app.js`, self-hosted fonts/QR assets, standalone HTML, and security headers. Vercel’s `public/` output is generated from the same source. No CDN runtime dependency is allowed.

The build computes the standalone inline-script hash and writes the same value into the generated headers. CI verifies that the hash, output files, and source/artifact checksums agree before deployment.

## Persistence and failure behavior

The storage queue is the only write path for vault data. It coalesces rapid edits, serializes encryption/transactions, exposes `flush()`, and retains the last committed generation on failure. Theme and language preferences may remain non-sensitive browser preferences, but notes, TOTP seeds, account passwords, backup envelopes, and decoder state never use a plaintext durable store.

`navigator.storage.persist()` is requested as a best-effort durability hint. The UI reports granted, denied, or unavailable without implying that browser deletion is impossible.

## Security boundaries and claims

- AES-GCM protects persisted vault bytes; the key is non-extractable and session-only.
- AAD binds ciphertext to `AeroPad|vault|v2|generation=N`.
- Strict CSP, self-hosted dependencies, SRI for build inputs where applicable, and artifact verification reduce deployment/supply-chain risk.
- The product says “encrypted at rest”, “local-first”, and “AeroPad does not upload vault content”. It does not say “zero-knowledge” or “nothing leaves the device”.
- Legal, privacy, license, and trademark documents are release prerequisites but are not cryptographic guarantees.

## Release evidence

The current release decision and exact verification evidence are recorded in
[`release-readiness.md`](release-readiness.md). The 2026-08-22 baseline is a
`GO` for a closed experimental local utility and a `NO-GO` for paid,
security-critical positioning until independent security review, trademark
clearance, and a clean release commit are complete.
