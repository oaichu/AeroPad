# AeroPad Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move AeroPad from a localStorage-only prototype to a tested, encrypted-by-default local-first security workbench with strict TOTP semantics, durable recovery, trustworthy browser UX, and reproducible artifacts.

**Architecture:** Keep the static/browser-only product boundary, but make `src/` the canonical implementation. A single IndexedDB `vault/current` record stores one versioned AES-GCM envelope containing notes and TOTP accounts; a serialized queue exposes durable `flush()` semantics. The browser bundle is generated from `src/app.js` and tested at unit, browser, migration, and artifact levels.

**Tech Stack:** Browser Web Crypto API, IndexedDB, vanilla HTML/CSS/JavaScript, Node’s built-in test runner, esbuild as a pinned build-only dependency, jsdom/browser E2E harness, and self-hosted QR/font assets.

**Spec:** `specs/security-remediation.md`, `specs/vault-schema.md`, `specs/totp-otpauth.md`, `DESIGN.md`, and `docs/architecture.md`

## Global Constraints

- Preserve the static browser-only boundary: no backend, account service, telemetry, remote search, or server-side decryption.
- Use `design/tokens-v1.json` for all new visual values; do not introduce unapproved colors, fonts, radii, or spacing.
- New vault content is encrypted before durable persistence; plaintext localStorage is migration input only.
- The v2 envelope uses PBKDF2-HMAC-SHA256 with 600,000 iterations, 16-byte salt, AES-256-GCM, 12-byte IV, and generation-bound AAD.
- TOTP accepts only `totp`, SHA1/SHA256/SHA512, digits 6/8, and periods 1–3600 seconds; unknown values fail visibly.
- Generated TOTP secrets are 32 Base32 characters; valid shorter imported secrets remain compatible.
- Every implementation unit must keep its diff within the stated limit, except the explicitly marked mechanical source relocation and generated lockfile.
- Every unit follows red → green → verify and must not edit a forbidden path.
- Root `app.js`, `public/`, `dist/`, and standalone HTML are generated/transition artifacts; they are never hand-edited.

---

### AATP-001: Harden Base32 and TOTP source modules

**Goal:** Make the tested TOTP source engine enforce the new entropy, option, algorithm, and per-period contract.

**Depends on:** None.
**Blast radius:** All future vault cards, decoder previews, QR imports, and tests that call `src/crypto/totp.js`.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/crypto/base32.js`
- Modify: `src/crypto/totp.js`
- Modify: `tests/base32.test.js`
- Modify: `tests/totp.test.js`

**Max diff:** ≤200 lines.

**Acceptance:** `npm test -- --test-name-pattern='Base32|TOTP'` passes and includes tests for a 32-character generated secret, 15/45/60-second periods, SHA-1/SHA-256/SHA-512, invalid algorithm/digits/period, and malformed secrets returning an unavailable result.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/crypto/otpauth.js`, `src/storage/**`, `public/**`, `dist/**`.

- [ ] **Step 1: Write failing tests.** Assert `Base32.randomSecret()` returns exactly 32 characters by default, all characters are in `A–Z2–7`, and explicit lengths still work. Add TOTP tests that compute the same secret at periods 15, 45, and 60, and reject unsupported algorithm/digit/period values.
- [ ] **Step 2: Run the focused tests.** Run `npm test -- --test-name-pattern='Base32|TOTP'`. Expected: the new default-length and validation assertions fail against the current source.
- [ ] **Step 3: Implement the minimum source change.** Add strict option validation before Web Crypto, preserve the RFC dynamic truncation, use the requested period for the counter, and map only the three supported algorithms.
- [ ] **Step 4: Run the focused tests again.** Expected: all focused tests pass.
- [ ] **Step 5: Run the full unit suite.** Run `npm test`. Expected: all existing and new tests pass.

### AATP-002: Make OTPAuth parsing strict and semantic

**Goal:** Reject HOTP and unsupported algorithm/digit/period values instead of silently reinterpreting them as TOTP/SHA-1/6/30.

**Depends on:** AATP-001.
**Blast radius:** Decoder imports, QR imports, generated URI compatibility, and vault account metadata.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/crypto/otpauth.js`
- Modify: `tests/otpauth.test.js`

**Max diff:** ≤180 lines.

**Acceptance:** `npm test -- --test-name-pattern='OTPAuth'` passes tests for HOTP rejection, unknown algorithm rejection, digits 7 rejection, invalid period rejection, canonical algorithm output, and valid SHA-256/60-second/8-digit parsing.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/crypto/totp.js`, `src/storage/**`, `public/**`, `dist/**`.

- [ ] **Step 1: Write failing parser tests.** Add cases for `otpauth://hotp/...`, `algorithm=MD5`, `digits=7`, `period=0`, `period=3601`, and a valid URI with mixed-case algorithm spelling.
- [ ] **Step 2: Run the parser tests.** Run `npm test -- --test-name-pattern='OTPAuth'`. Expected: the new strictness assertions fail because the current parser accepts or preserves unsupported values.
- [ ] **Step 3: Implement strict host/type and field validation.** Return stable error codes from the contract and canonicalize accepted fields without fallback.
- [ ] **Step 4: Re-run parser and full unit tests.** Run `npm test -- --test-name-pattern='OTPAuth'` followed by `npm test`. Expected: both pass.

### AATP-003: Add bounded versioned vault crypto

**Goal:** Provide a pure crypto module that validates v2 envelopes before KDF work and binds ciphertext to its generation with AAD.

**Depends on:** None.
**Blast radius:** New storage layer, unlock flow, password changes, backup import/export.
**Model tier:** strong.

**Files allowed:**
- Create: `src/crypto/vault-crypto.js`
- Create: `tests/vault-crypto.test.js`

**Max diff:** ≤200 lines.

**Acceptance:** `node --test tests/vault-crypto.test.js` covers round-trip encryption, wrong password, wrong generation/AAD, malformed Base64, oversized ciphertext, out-of-range iterations, invalid IV/salt lengths, and rejection before `deriveKey` is called.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/storage/**`, `src/crypto/base32.js`, `src/crypto/totp.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Write the failing contract tests.** Define the test fixtures for a small payload, v2 envelope, tampered AAD, malformed bounds, and a KDF spy that proves invalid input does not invoke derivation.
- [ ] **Step 2: Run the new test file.** Run `node --test tests/vault-crypto.test.js`. Expected: imports fail because the module does not exist.
- [ ] **Step 3: Implement the module.** Export bounded envelope validation, PBKDF2 key derivation, AES-GCM encrypt/decrypt, Base64 helpers, and generation-AAD construction. Use non-extractable AES keys.
- [ ] **Step 4: Run the test file and full suite.** Expected: both pass with no unhandled crypto errors.

### AATP-004: Add a serialized vault commit queue

**Goal:** Make `flush()` and last-committed-generation behavior independently testable before wiring IndexedDB into the UI.

**Depends on:** AATP-003.
**Blast radius:** Every autosave, lock, password change, backup, and migration operation.
**Model tier:** strong.

**Files allowed:**
- Create: `src/storage/vault-store.js`
- Create: `src/storage/memory-adapter.js`
- Create: `tests/vault-store.test.js`

**Max diff:** ≤200 lines.

**Acceptance:** `node --test tests/vault-store.test.js` proves serialized writes, coalescing, `flush()` completion only after commit, generation monotonicity, and preservation of the previous record on encryption/adapter failure.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/crypto/**`, `src/storage/indexeddb-adapter.js`, `src/storage/legacy-migration.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Write failing queue tests.** Use the memory adapter with controllable promises and assert the exact commit ordering and failure behavior.
- [ ] **Step 2: Run the focused test.** Expected: module/queue assertions fail.
- [ ] **Step 3: Implement `VaultStore`.** Expose `loadCurrent()`, `commit(payload)`, `flush()`, and `getStatus()`. Keep the prior committed value until the new commit resolves.
- [ ] **Step 4: Run focused and full unit tests.** Expected: all pass.

### AATP-005: Implement the IndexedDB adapter

**Goal:** Persist the single `vault/current` record in an actual IndexedDB transaction.

**Depends on:** AATP-004.
**Blast radius:** Browser durability and all recovery scenarios.
**Model tier:** strong.

**Files allowed:**
- Create: `src/storage/indexeddb-adapter.js`
- Modify: `tests/vault-store.test.js`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** The browser E2E creates a vault, reloads it, verifies one `vault/current` record, injects a failed transaction, and confirms the previous generation remains available. `npm test` remains green.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/crypto/**`, `src/storage/legacy-migration.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Add browser acceptance assertions.** Extend the E2E harness with a controllable IndexedDB failure and generation checks.
- [ ] **Step 2: Run the new E2E assertions.** Expected: they fail because the adapter is absent.
- [ ] **Step 3: Implement database open/upgrade, `getCurrent`, and `putCurrent`.** The write method must resolve from `transaction.oncomplete`, reject on `onerror`/`onabort`, and never use two stores for one commit.
- [ ] **Step 4: Run `npm test` and the E2E script.** Expected: existing behavior plus the new transaction assertions pass.

### AATP-006: Add safe legacy localStorage migration

**Goal:** Import valid legacy data without treating missing or mixed-generation records as empty data.

**Depends on:** AATP-003, AATP-004, AATP-005.
**Blast radius:** Existing users’ notes, TOTP accounts, corrupt backups, and first encrypted boot.
**Model tier:** strong.

**Files allowed:**
- Create: `src/storage/legacy-migration.js`
- Create: `tests/legacy-migration.test.js`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** Tests cover two valid plaintext arrays, two valid legacy envelopes, one-sided envelope, mixed generation, malformed values, and plaintext corrupt backups. No case silently produces an empty side.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/crypto/base32.js`, `src/crypto/totp.js`, `src/crypto/otpauth.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Write migration fixtures and failing tests.** Preserve raw values in every non-committed path and return stable recovery states.
- [ ] **Step 2: Run `node --test tests/legacy-migration.test.js`.** Expected: failures because the migration module is absent.
- [ ] **Step 3: Implement one-shot migration parsing.** Keep raw localStorage untouched until a v2 commit succeeds; expose `legacy-recovery-required` for ambiguous input.
- [ ] **Step 4: Run migration tests and browser corruption scenarios.** Expected: all pass and no raw data is deleted prematurely.

### AATP-007: Establish the canonical source entry and deterministic bundle

**Goal:** Make `src/app.js` the browser controller source and generate the runtime bundle/standalone output from it.

**Depends on:** AATP-001 through AATP-006.
**Blast radius:** Every browser entry point and deployment artifact.
**Model tier:** strong.

**Files allowed:**
- Create: `src/app.js` (mechanical relocation of the current controller)
- Create: `scripts/build.mjs`
- Modify: `package.json`
- Create: `package-lock.json`
- Modify: `index.html`

**Max diff:** ≤200 logical lines; the mechanical relocation of the existing controller and generated npm lockfile are explicit exceptions because the source-of-truth change cannot be performed as a small semantic diff.

**Acceptance:** `npm run build` bundles `src/app.js`, emits `app.js`/`dist`/`public` outputs from one source, and the standalone builder consumes the generated bundle. `npm test` still passes.

**Forbidden paths:** `styles.css`, `src/crypto/**`, `src/storage/**`, `tests/**`, `_headers`, `vercel.json`, hand edits to generated `app.js`, `dist/**`, `public/**`.

- [ ] **Step 1: Create the canonical controller entry.** Move/copy the current browser controller into `src/app.js` without behavior changes; keep the generated root bundle as a transition artifact.
- [ ] **Step 2: Add the pinned build dependency and failing build check.** Add `esbuild` to `devDependencies`, add `build:app`, `build`, and `sync:public` scripts, and assert that the output bundle exists.
- [ ] **Step 3: Implement deterministic bundling.** Bundle `src/app.js` as a browser IIFE, copy canonical HTML/CSS/assets, and invoke the standalone generator after the bundle is current.
- [ ] **Step 4: Run `npm run build`, `npm test`, and the current E2E script.** Expected: generated artifacts boot and the baseline remains green.

### AATP-008: Remove duplicated production crypto engines

**Goal:** Make production use the tested Base32, TOTP, and OTPAuth modules instead of declarations duplicated inside the browser controller.

**Depends on:** AATP-007.
**Blast radius:** Generator, decoder, vault cards, QR URI generation, and E2E code values.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `src/crypto/base32.js`
- Modify: `src/crypto/totp.js`
- Modify: `src/crypto/otpauth.js`

**Max diff:** ≤200 lines.

**Acceptance:** `rg -n 'const Base32|async function generateTOTP|function normalizeAlgo|function parseAndDisplayOTPString' src/app.js` shows no duplicate crypto engine definitions, while `npm test`, `npm run build`, and `node scripts/e2e-verify.mjs` pass.

**Forbidden paths:** `app.js`, `index.html`, `styles.css`, `src/storage/**`, `tests/**`, `dist/**`, `public/**`.

- [ ] **Step 1: Add integration assertions.** Add a source scan/test that fails when duplicate Base32/TOTP declarations return to `src/app.js`.
- [ ] **Step 2: Run the assertion.** Expected: it fails against the relocated controller.
- [ ] **Step 3: Import the source modules and delete only the duplicate declarations.** Keep UI adapters thin and use the canonical error/normalization contract.
- [ ] **Step 4: Build and run all unit/E2E checks.** Expected: production codes match the source reference vectors for all supported algorithms and periods.

### AATP-009: Wire the v2 storage lifecycle into the controller

**Goal:** Replace production vault reads/writes with `VaultStore` and make boot/unlock/save use one encrypted snapshot.

**Depends on:** AATP-003 through AATP-008.
**Blast radius:** Boot lock screen, notes, TOTP accounts, password setup/change/remove, reload durability.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `src/crypto/vault-crypto.js`
- Modify: `src/storage/vault-store.js`
- Modify: `src/storage/indexeddb-adapter.js`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines; if controller wiring exceeds this, split the password-management handlers into AATP-010 before changing behavior.

**Acceptance:** The E2E lifecycle creates a v2 vault, reloads, unlocks, edits notes and TOTP together, and proves only one encrypted `vault/current` record changes. No new vault save writes `aeropad_notes` or `aeropad_totp`.

**Forbidden paths:** `index.html`, `styles.css`, `src/crypto/base32.js`, `src/crypto/totp.js`, `src/crypto/otpauth.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Add failing E2E assertions.** Inspect IndexedDB and assert that a failed second-side write cannot create a mixed vault; assert ciphertext does not contain note/secret plaintext.
- [ ] **Step 2: Run the storage lifecycle E2E.** Expected: it fails because the controller still uses the legacy keys.
- [ ] **Step 3: Replace boot/persist paths with one snapshot commit.** Keep theme/lang preferences separate and route notes/TOTP mutations through the queue.
- [ ] **Step 4: Run `npm run build`, unit tests, and E2E.** Expected: encrypted reload and failed-commit behavior pass.

### AATP-010: Finish encryption-by-default, migration, flush, and auto-lock UX

**Goal:** Make the UI communicate durable state and prevent lock/reload from interrupting pending encrypted writes.

**Depends on:** AATP-006 and AATP-009.
**Blast radius:** Security modal, lock overlay, autosave, inactivity behavior, error announcements, secret cleanup.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `index.html`
- Modify: `styles.css`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** Browser checks cover pending/committed/save-failed states, `Lock now` awaiting `flush()`, 15-minute inactivity lock using a fake clock, visibility return, and clearing password/revealed secret fields after lock.

**Forbidden paths:** `src/crypto/**`, `src/storage/**`, `src/notes/**`, `public/**`, `dist/**`, `vercel.json`, `_headers`.

- [ ] **Step 1: Write failing browser checks.** Simulate a delayed commit and assert the UI does not say Saved or clear the key until completion; simulate rejection and assert the previous generation remains usable.
- [ ] **Step 2: Run the focused E2E checks.** Expected: current fire-and-forget save and reload behavior fails them.
- [ ] **Step 3: Implement the state machine and lock deadline.** Use accessible status text, await `flush()`, disable destructive actions while pending, and clear transient secret DOM values.
- [ ] **Step 4: Run the full unit/E2E suite.** Expected: the security UX checks pass with no unhandled promise rejection.

### AATP-011: Add encrypted backup and restore

**Goal:** Give users a portable, checksum-verified `.aeropad` recovery path without exporting plaintext JSON.

**Depends on:** AATP-003, AATP-009, AATP-010.
**Blast radius:** Recovery UX, import/export, password handling, migration safety.
**Model tier:** strong.

**Files allowed:**
- Create: `src/storage/backup.js`
- Create: `tests/backup.test.js`
- Modify: `src/app.js`
- Modify: `index.html`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** Tests and E2E create an encrypted `.aeropad` payload, verify checksum/version, reject tampering/wrong password, restore into a fresh profile, and never offer a plaintext secret export through the backup control.

**Forbidden paths:** `styles.css`, `src/crypto/base32.js`, `src/crypto/totp.js`, `src/crypto/otpauth.js`, `src/notes/**`, `public/**`, `dist/**`.

- [ ] **Step 1: Write failing backup tests.** Cover stable envelope checksum, malformed outer format, tampered ciphertext, wrong password, and successful restore.
- [ ] **Step 2: Run `node --test tests/backup.test.js`.** Expected: the module is absent.
- [ ] **Step 3: Implement backup creation/import around the existing encrypted envelope.** Verify all bounds before replacement and commit the imported record atomically.
- [ ] **Step 4: Add the UI actions and restore confirmation.** Display last-backup time and reminder state.
- [ ] **Step 5: Run unit, build, and E2E checks.** Expected: recovery survives a fresh database/profile.

### AATP-012: Integrate strict per-account TOTP refresh behavior

**Goal:** Ensure production cards and decoder previews refresh at each account’s period and show the actual algorithm/digits.

**Depends on:** AATP-001, AATP-002, AATP-008, AATP-009.
**Blast radius:** Live OTP display, copy behavior, countdowns, decoder preview, QR-imported metadata.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `scripts/e2e-verify.mjs`
- Modify: `tests/totp.test.js`

**Max diff:** ≤200 lines.

**Acceptance:** E2E crosses 15-, 30-, 45-, and 60-second boundaries and proves the displayed/copyable code changes at the account window, while the footer reports the account’s actual algorithm and digits.

**Forbidden paths:** `index.html`, `styles.css`, `src/storage/**`, `src/crypto/vault-crypto.js`, `public/**`, `dist/**`.

- [ ] **Step 1: Add fake-clock tests and E2E cases.** Cover multiple accounts with different periods and a decoder URI with a non-default period.
- [ ] **Step 2: Run the focused tests.** Expected: the 30-second global gate leaves at least one account stale.
- [ ] **Step 3: Replace the global window gate with per-account window indexes.** Keep one-second progress updates and force refresh on visibility return.
- [ ] **Step 4: Run unit, build, and E2E acceptance.** Expected: no stale code is copied after any supported period boundary.

### AATP-013: Remove DOM injection paths and improve secret/modal semantics

**Goal:** Make user-controlled messages text-only and make secret fields/dialogs accessible and masked by default.

**Depends on:** AATP-010 and AATP-012.
**Blast radius:** Toasts, notes/QR labels, TOTP/password cards, modal/lock accessibility.
**Model tier:** strong.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `index.html`
- Modify: `styles.css`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** A DOM sink test injects `<img src=x onerror=...>` through a note title/toast path and finds no element or executable attribute. Accessibility checks find `role=dialog`, labelled controls, focus return, `type=password` defaults, and correct delete/error copy.

**Forbidden paths:** `src/crypto/**`, `src/storage/**`, `src/notes/**`, `_headers`, `vercel.json`, `public/**`, `dist/**`.

- [ ] **Step 1: Add the failing sink/accessibility checks.** Inspect toasts, translated labels, preview rendering, QR errors, secret fields, and modal keyboard behavior.
- [ ] **Step 2: Run the focused browser checks.** Expected: the existing `innerHTML` toast and secret inputs fail.
- [ ] **Step 3: Replace user-controlled `innerHTML` with `textContent`/static DOM nodes.** Keep fixed SVG markup separate from message text; escape/render note markdown through the existing safe path.
- [ ] **Step 4: Add dialog semantics, focus trap/return, reveal controls, and accurate labels.** Do not expose seeds/passwords by default.
- [ ] **Step 5: Run build, E2E, and `git diff --check`.** Expected: all pass.

### AATP-014: Bound QR decoding and improve local note search

**Goal:** Prevent large-image mobile freezes and make local search responsive for realistic vault sizes.

**Depends on:** AATP-013.
**Blast radius:** Decoder import performance and note list behavior.
**Model tier:** cheap.

**Files allowed:**
- Modify: `src/app.js`
- Modify: `src/notes/notes-manager.js`
- Modify: `tests/notes.test.js`
- Modify: `scripts/e2e-verify.mjs`

**Max diff:** ≤200 lines.

**Acceptance:** QR E2E feeds an oversized image and proves the decoded canvas edge is ≤2048px; note tests cover 125ms debounce-compatible search normalization, diacritics, title-first scoring, and no remote call.

**Forbidden paths:** `index.html`, `styles.css`, `src/crypto/**`, `src/storage/**`, `public/**`, `dist/**`, package metadata.

- [ ] **Step 1: Add failing image/search tests.** Include a 4096px fixture, accented Vietnamese text, a title match, and a content-only match.
- [ ] **Step 2: Run focused tests/E2E.** Expected: current full-resolution extraction and substring-only search fail.
- [ ] **Step 3: Add downsampling and cached normalized search corpus.** Use the longest-edge limit and title score before content score.
- [ ] **Step 4: Run `npm test` and E2E.** Expected: behavior passes without new network activity.

### AATP-015: Self-host runtime dependencies and tighten headers

**Goal:** Remove runtime CDN/font requests and make production CSP self-only.

**Depends on:** AATP-007 and AATP-013.
**Blast radius:** First paint, QR generation/decoding, CSP, privacy wording, standalone artifact.
**Model tier:** strong.

**Files allowed:**
- Create/modify: `vendor/**`
- Modify: `index.html`
- Modify: `_headers`
- Modify: `vercel.json`
- Modify: `scripts/build.mjs`

**Max diff:** ≤200 logical lines; vendored third-party files are reviewed immutable assets and are excluded from the logical diff limit.

**Acceptance:** `rg -n 'cdn.jsdelivr|fonts.googleapis|fonts.gstatic|rsms.me' index.html _headers vercel.json` returns no runtime references; a built page uses `script-src 'self'`, no `unsafe-inline` for styles unless a generated hash is required, and QR E2E still passes offline.

**Forbidden paths:** `src/app.js`, `src/crypto/**`, `src/storage/**`, `tests/**`, `README.md`, `dist/**`, `public/**`.

- [ ] **Step 1: Add an offline E2E assertion and header scan.** Expected: current CDN references fail.
- [ ] **Step 2: Copy pinned QR libraries and required font assets into `vendor/`.** Record versions and licenses for the notices task.
- [ ] **Step 3: Update HTML/build/header policies.** Keep only local runtime script/style/font/image sources; add `Permissions-Policy` and `Referrer-Policy: no-referrer`.
- [ ] **Step 4: Run build, offline E2E, and header scan.** Expected: QR and visual shell remain functional without network.

### AATP-016: Make dependencies, artifacts, and CI reproducible

**Goal:** Declare every dependency, verify generated artifacts, and require unit → E2E → build checks in CI.

**Depends on:** AATP-007 and AATP-015.
**Blast radius:** Developer setup, deployment safety, drift detection, release confidence.
**Model tier:** strong.

**Files allowed:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `scripts/verify-build.mjs`
- Create: `.github/workflows/verify.yml`
- Modify: `.gitignore`

**Max diff:** ≤200 logical lines; generated lockfile changes are an explicit mechanical exception.

**Acceptance:** A clean install followed by `npm run verify` runs unit tests, E2E, build, artifact/hash verification, and `git diff --exit-code` against generated outputs. CI invokes the same command.

**Forbidden paths:** `src/**`, `app.js`, `index.html`, `styles.css`, `public/**`, `dist/**`, `_headers`, `vercel.json`.

- [ ] **Step 1: Add the failing verifier.** Assert package dependencies are declared, generated outputs exist, root/public/dist hashes agree where intended, and the standalone CSP hash matches.
- [ ] **Step 2: Run `npm run verify`.** Expected: it fails on undeclared jsdom/jsQR/qrcode-generator and current dist drift.
- [ ] **Step 3: Declare exact build/test dependencies and wire the workflow.** Use one lockfile and the project’s npm commands.
- [ ] **Step 4: Run the clean verification loop locally.** Expected: unit, E2E, build, and artifact checks pass.

### AATP-017: Correct product, license, privacy, and security claims

**Goal:** Make the public product surface match the actual threat model and distribution licenses.

**Depends on:** AATP-015 and AATP-016.
**Blast radius:** README, package metadata, public trust, license compliance, commercial review.
**Model tier:** strong.

**Files allowed:**
- Modify: `README.md`
- Modify: `package.json`
- Create: `LICENSE`
- Create: `THIRD_PARTY_NOTICES.md`
- Create: `docs/SECURITY-AND-PRIVACY.md`

**Max diff:** ≤200 lines excluding exact MIT license text and generated third-party license text.

**Acceptance:** No product metadata or README claim uses “zero-knowledge”, “Apple-grade”, “Apple + Web3”, “decentralized”, or literal “no data ever leaves the device”; the docs state the same-origin threat model, backup limitations, no telemetry, data categories, and third-party licenses.

**Forbidden paths:** `src/**`, `index.html`, `styles.css`, `app.js`, `public/**`, `dist/**`, `_headers`, `vercel.json`.

- [ ] **Step 1: Add a claim-policy test/scan.** Make the forbidden marketing terms fail the check outside the explicit threat-model explanation.
- [ ] **Step 2: Update README/package copy and create license/notice/security documents.** State “encrypted at rest”, “local-first”, and “AeroPad does not upload vault content” precisely.
- [ ] **Step 3: Run the claim scan, unit tests, and build verifier.** Expected: public copy and license inventory pass.

### AATP-018: Commercial release verification packet

**Goal:** Produce final evidence that the remediation plan is complete and identify only explicit post-beta work.

**Depends on:** AATP-001 through AATP-017.
**Blast radius:** Release decision only; no runtime behavior.
**Model tier:** strong.

**Files allowed:**
- Modify: `docs/architecture.md`
- Modify: `specs/security-remediation.md`
- Create: `docs/release-readiness.md`

**Max diff:** ≤160 lines.

**Acceptance:** `npm run verify` passes; the release packet records test counts, artifact hashes, migration/recovery evidence, claim scan results, known residual risks, and a clear `GO`/`NO-GO` recommendation.

**Forbidden paths:** `src/**`, `app.js`, `index.html`, `styles.css`, `public/**`, `dist/**`, `package.json`, all runtime dependencies.

- [ ] **Step 1: Run the full verification loop.** Capture unit, browser, migration, backup, corruption, CSP, dependency, and artifact results.
- [ ] **Step 2: Write the evidence packet.** Separate shipped P0/P1 behavior from deferred HOTP/PWA/camera/device-transfer work.
- [ ] **Step 3: Run the final documentation/claim scan.** Expected: no placeholders, contradictory claims, or unverified “Saved”/encryption language remain.

## Plan self-review

- **Spec coverage:** Vault atomicity, backup/restore, bounded envelopes, KDF floor, AAD, migration, flush, auto-lock, strict TOTP, per-period timers, DOM safety, QR bounds, local search, self-hosting, CSP, artifact drift, dependency declarations, legal wording, and release evidence each have a named AATP.
- **Source ownership:** AATP-007 establishes `src/app.js`; AATP-008 removes duplicate crypto; AATP-016 makes generated artifacts verifiable.
- **Type consistency:** `VaultStore` exposes `loadCurrent()`, `commit(payload)`, `flush()`, and `getStatus()`; the IndexedDB adapter exposes `getCurrent()` and `putCurrent(record)`; v2 envelope and TOTP field names match the specs.
- **Placeholder scan:** No implementation task relies on “TBD”, “TODO”, “implement later”, or unspecified edge-case handling.
- **Scope boundary:** HOTP, PWA, camera scanning, and device transfer remain explicit post-core work in the P2 section and are not silently folded into the commercial remediation gate.
