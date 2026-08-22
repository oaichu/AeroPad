# AeroPad Release Readiness

**Evidence date:** 2026-08-22
**Scope:** current working tree after AATP-001 through AATP-017

## Decision

**NO-GO for a paid or security-critical commercial release.**

**GO for a closed experimental beta as a local utility**, provided the
current local-first wording, backup warning, and same-origin threat model are
kept intact. This is a release decision for the current evidence baseline,
not an independent security certification.

## Verification evidence

Fresh `npm run verify` completed with exit code 0 and reported:

| Gate | Result |
| --- | --- |
| Claim-policy preflight | `claim policy: PASS` |
| Dependency declarations and lockfile | `PASS` |
| Self-hosted runtime and CSP inputs | `PASS` |
| Unit suite | 44 passed, 0 failed |
| Browser E2E suite | 96/96 passed |
| Generated artifacts and vendor hashes | 5 artifacts, `PASS` |
| Standalone CSP hashes | `PASS` |
| Deterministic build comparison | `PASS` |
| Full verification | `PASS` |

`npm audit --omit=dev` is part of the release check and must report zero
vulnerabilities on the final release commit. The current local audit result is
zero vulnerabilities.

## Artifact evidence

The verifier generated identical output on both build passes. SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `index.html` | `6116ac8582a7a63939da4f517e36c978f5c2e6b7c2ba2ae4495640f14f6461d1` |
| `styles.css` | `7817bd342ecd3cf09a6108a5e96f27bdc2627c8cd670fc3a058ccbb11c0fc49e` |
| `app.js` | `13bc31de2dc0b3ac787970716681f4b8e4cfb8a432031c471e07b0e3986251b8` |
| `aeropad-standalone.html` | `0bda8b6d3d8457c819ff4733d176ebca8e47e684642b6f0c8409597d304a4d36` |
| `_headers` | `e3c55d3a66b56bed50845497ac0b6e4a4dade03883374f170e9da1144dbb387c` |

Standalone inline-script CSP hash:
`aNCxmbGYqKNC25ZygG3emudZEGy8jR/7QgVqlZEhvLw=`.

## Data-safety and recovery evidence

- Legacy corruption tests preserve both raw sides and require recovery for
  ambiguous or one-sided data (`REL-001`, `REL-002`, and migration suites).
- v2 encryption tests cover AES-GCM/AAD, wrong passwords, malformed bounded
  envelopes, and preservation of the previous generation after a failed
  transaction.
- Browser E2E covers one encrypted IndexedDB snapshot, reload/abort behavior,
  flush-before-lock, save-state reporting, auto-lock cleanup, and encrypted
  `.aeropad` backup export/restore. Wrong backup passwords do not replace the
  current record.
- TOTP E2E covers 15s, 30s, 45s, and 60s account windows, SHA-256/8-digit
  imports, QR bounds at a 2048px longest edge, and strict parser behavior.
- Security UX E2E covers text-only user-controlled toast rendering, masked
  secrets, reveal controls, dialog semantics, labels, focus traps, and focus
  return.

## Shipped versus deferred

Shipped core remediation includes the single encrypted IndexedDB snapshot,
serialized commits and `flush()`, encrypted backup/restore, 160-bit generated
secrets, strict TOTP semantics, bounded envelope validation, inactivity lock,
DOM cleanup, QR downsampling, local ranked search, self-hosted dependencies,
strict CSP, deterministic artifacts, and claim/license/privacy documentation.

Explicit post-beta work is HOTP with counter UX, PWA/offline installation,
camera scanning, bulk migration, encrypted device-to-device transfer, tags or
richer local search, independent security review, and trademark clearance.

## Residual risks and release conditions

- A compromised deployment, malicious future update, hostile same-origin
  script, browser extension, or already-compromised device can read plaintext
  while unlocked. Web Crypto does not remove this web-app boundary.
- Browser storage remains best-effort. A forgotten master password is not
  recoverable; encrypted backups must be stored and periodically restored by
  the user.
- The current evidence is from a dirty local working tree. Before any public
  release, regenerate the packet from the exact release commit in a clean
  checkout and repeat `npm run verify`, `npm audit --omit=dev`, and the claim
  scan.
- Paid/security-critical positioning additionally requires independent
  security review, trademark clearance, operator privacy documentation, and
  final review of third-party notices.

## Final gate

The core remediation plan is verified for closed-beta use. The commercial
security-vault gate remains `NO-GO` until every release condition above has
fresh evidence attached to the exact release commit.
