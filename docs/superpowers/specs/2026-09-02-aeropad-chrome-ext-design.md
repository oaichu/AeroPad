# AeroPad Chrome Extension — Design Spec

**Date:** 2026-09-02
**Status:** Draft, awaiting user review
**Path:** Architectural (new project)
**Source project:** https://github.com/oaichu/AeroPad (MIT)

## 1. Summary

A Manifest V3 Chrome extension that brings AeroPad's local-first 2FA authenticator and encrypted notes to any website. The extension surfaces codes via a toolbar popup, auto-detects 2FA inputs on every page, and fills them on click. All secrets are encrypted at rest with AES-256-GCM under a user-chosen master password; the extension makes zero network calls.

## 2. Goals

1. **Port AeroPad's full feature set** — TOTP vault, encrypted notes, QR studio, multilingual UI — into a Chrome extension.
2. **Fast on every website** — content script auto-detects 2FA inputs and offers one-click fill without page mutation or shadow DOM.
3. **Local-first** — no backend, no account, no telemetry, no auto-update. Manual sync via the portable `.aeropad` file.
4. **Auditable** — vanilla TypeScript + Preact, no remote dependencies, strict CSP, all third-party code vendored.

## 3. Non-Goals

- Browser sync via `chrome.storage.sync` of the encrypted vault (only metadata is synced; the vault itself stays in `local`).
- Cloud sync via Google Drive / Dropbox / WebDAV.
- Side panel UI, command bar, or omnibox integration (deferred to a later release).
- Auto-submit after fill (deferred).
- Browser support beyond Chromium-based browsers (Firefox is out of scope for v1).

## 4. Architecture

Four execution contexts, each with a single responsibility:

| Context | Role | Lifetime |
|---|---|---|
| **Service Worker** (`src/background/service-worker.ts`) | Vault gatekeeper: holds derived `CryptoKey` in memory, serves decrypted codes/notes, handles `.aeropad` import/export | Wakes on message; dies after ~30 s idle |
| **Popup** (`src/popup/`) | The "app" — Preact UI for listing codes, notes, settings, password prompt | Tied to popup window |
| **Content Script** (`src/content/detector.ts`) | Lightweight detector — finds 2FA inputs on the active page, injects a tiny inline icon, on click opens the popup with the matching entry pre-selected | Active on every page (declared in manifest) |
| **Options Page** (`src/options/`) | Full-page Preact UI for bulk operations: manage entries, import/export `.aeropad`, change password, language | New tab |

**Storage layout (chrome.storage):**

- `local.vaultBlob` — `{ v: 1, salt, iv, ciphertext }` (AES-256-GCM-encrypted JSON of `{ codes, notes }`)
- `local.vaultMeta` — `{ version, kdfParams, createdAt, modifiedAt, entryCount }` (unencrypted metadata, used for diagnostics)
- `sync.deviceList` — `[{ deviceId, name, lastSeen }]` (small, for cross-device awareness)
- `local.sessionLock` — `{ lastUnlockedAt, autoLockMinutes }`

**MV3 considerations:**

- Service worker can be killed at any time → derived key is lost → next fill re-prompts for password (acceptable, matches AeroPad's threat model).
- No `eval`, no remote scripts. Strict CSP `script-src 'self'; object-src 'self'`.
- All libraries vendored locally (no CDN), matching AeroPad.
- Background persistence: rely on `chrome.runtime.connect` from the popup to keep the SW alive while the popup is open; let it die otherwise.

## 5. Tech Stack

- **Language:** TypeScript (strict mode, `noUncheckedIndexedAccess: true`)
- **UI framework:** Preact 10.x with `preact/compat` shim for hooks ergonomics
- **Build tool:** Vite 5.x with `@crxjs/vite-plugin` for MV3 bundling
- **Testing:** Vitest (unit, integration with jsdom), Playwright (e2e with real Chrome)
- **Linting:** ESLint (typescript-eslint) + Prettier
- **No runtime dependencies** beyond Preact itself and a vendored QR decoder (`qr.ts`, ~10 KB)
- **Total bundle size target:** ≤ 40 KB (uncompressed)

## 6. Components

### 6.1 Popup (`src/popup/`)

- `main.tsx` — Preact entry, mounts `<App />`
- `App.tsx` — routes between `UnlockDialog` and the main view based on SW lock state (polled via `SW.isUnlocked()`)
- `components/UnlockDialog.tsx` — password prompt with zxcvbn-style strength hint
- `components/CodeList.tsx` — list of TOTP entries with live countdown ring
- `components/CodeItem.tsx` — single entry: issuer, account, current code, countdown; click to copy
- `components/NotesList.tsx` / `NoteEditor.tsx` — markdown notes (matches AeroPad)
- `components/AddEntryDialog.tsx` — manual secret entry or QR scan (delegates to `qr.ts` in an offscreen document)
- `components/SettingsMenu.tsx` — lock now, change password, language, open options
- `styles.css` — Preact-app CSS, themed via CSS variables for light/dark

### 6.2 Service Worker (`src/background/service-worker.ts`)

**State (in memory only):**

- `derivedKey: CryptoKey | null`
- `decryptedVault: { codes: CodeEntry[]; notes: Note[] } | null`
- `autoLockTimer: ReturnType<typeof setTimeout> | null`

**Message handlers (typed via `lib/messages.ts`):**

- `unlock(password)` — derive key, decrypt vault, keep in memory, start auto-lock timer
- `lock()` — zero out key and vault, cancel timer
- `isUnlocked()` — returns `boolean`
- `getCodes()` / `getCode(id)` — return TOTP code (current digits, computed from secret + clock)
- `addEntry(entry)` / `updateEntry(id, patch)` / `deleteEntry(id)` / `reorderEntries(orderedIds)`
- `getNotes()` / `saveNote(note)` / `deleteNote(id)`
- `exportAeropad(password?)` — produce portable backup file
- `importAeropad(file, password, strategy: 'replace' | 'merge')` — restore from backup
- `fillOnTab(tabId, entryId)` — sends `fill_command` to the content script
- `changeMasterPassword(oldPassword, newPassword)` — re-encrypts vault with new key

**Side effects:** every mutation re-encrypts the vault and writes `local.vaultBlob`. `local.vaultMeta.modifiedAt` is updated. `sync.deviceList` is touched on unlock.

**Lifecycle:** registers `chrome.commands` listener for `fill-current` hotkey (default `Ctrl+Shift+F`).

### 6.3 Content Script (`src/content/detector.ts`)

- Runs at `document_idle` on `<all_urls>`
- One `MutationObserver` watches for new `<input>` elements (added to the observer once at startup)
- **Detection heuristics** (first match wins):
  1. `input[autocomplete="one-time-code"]`
  2. `input[inputmode="numeric"]` appearing **after** a `type="password"` field in the same form
  3. `input[name*="otp" | "2fa" | "token" | "code" | "verification"]` (case-insensitive)
- On match: injects a tiny **inline `<button>`** (no Shadow DOM, per design decision) styled to look like a normal icon, positioned next to the input
- On click: posts `fill_request` to SW with the field's bounding rect; SW opens the popup with `?action=fill&domain=<host>&field=<selector>`
- **Never reads `input.value`** — only fills
- **Cleanup:** the icon is removed after fill (one-shot per page); the observer disconnects on `pagehide`

### 6.4 Options Page (`src/options/`)

- Full-page Preact UI, reuses popup components where possible
- Unique screens:
  - **Import / Export** — drag-and-drop or file picker for `.aeropad`; strategy chooser (replace / merge)
  - **Change Password** — current password + new password (re-encrypts vault)
  - **Devices** — list of devices from `sync.deviceList`, remove old ones
  - **Language** — picker (10 languages: en, vi, zh, ko, ja, es, id, ar, hi, pt)
  - **Auto-lock** — slider (1 min to 24 h, default 15)
  - **Per-site controls** — whitelist / blacklist domains for the content script detector

### 6.5 Shared Lib (`src/lib/`)

- `crypto.ts` — `deriveKey(password, salt)`, `encrypt(plaintext, key)`, `decrypt(ciphertext, key)`, `randomBytes(n)`, base64url helpers
- `totp.ts` — RFC 6238: `totp(secret, { algorithm, digits, period, t })`; supports HMAC-SHA1/256/512, 6/8 digits, configurable period
- `storage.ts` — typed `chrome.storage.local` and `chrome.storage.sync` wrappers; keys are exported as constants
- `aeropad-format.ts` — `serialize(vault, password?)` / `parse(file, password?)`; versioned JSON: `{ v, kdf: { algo, iter, salt }, iv, ciphertext, meta }`
- `messages.ts` — discriminated-union message protocol for popup ↔ SW ↔ content; no `any` leakage
- `i18n.ts` — locale loader, RTL detection (`ar` switches `dir="rtl"`)
- `qr.ts` — vendored QR decoder (jsQR or equivalent), ~10 KB, no CDN
- `domain-match.ts` — pattern matcher for whitelist/blacklist

### 6.6 Manifest (`manifest.json`)

```jsonc
{
  "manifest_version": 3,
  "name": "AeroPad",
  "version": "0.1.0",
  "description": "Local-first 2FA & encrypted notes for every website.",
  "permissions": ["storage", "scripting", "activeTab", "commands", "offscreen"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "dist/background/service-worker.js", "type": "module" },
  "action": {
    "default_popup": "dist/popup/index.html",
    "default_title": "AeroPad",
    "default_icon": { "16": "icons/16.png", "48": "icons/48.png", "128": "icons/128.png" }
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["dist/content/detector.js"],
      "run_at": "document_idle",
      "all_frames": false
    }
  ],
  "options_page": "dist/options/options.html",
  "commands": {
    "fill-current": { "suggested_key": { "default": "Ctrl+Shift+F", "mac": "Command+Shift+F" } }
  },
  "content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }
}
```

## 7. Data Flow

### 7.1 First-time setup

1. User clicks extension icon → popup opens → `SW.isUnlocked()` returns `false` and `local.vaultBlob` is empty → popup shows **Create Vault** screen
2. User enters master password (min 8 chars, zxcvbn strength hint)
3. Popup generates `salt: Uint8Array(16)` via `crypto.getRandomValues`
4. Popup calls `SW.createVault(password)`:
   - Derives `key = PBKDF2-SHA256(password, salt, 600_000)`
   - Creates empty `Vault = { codes: [], notes: [] }`
   - Encrypts with AES-256-GCM (random `iv: 12 bytes`)
   - Persists `local.vaultBlob = { v: 1, salt, iv, ciphertext }`
   - Persists `local.vaultMeta = { version: 1, kdfParams: { algo: 'PBKDF2-SHA256', iter: 600_000 }, createdAt, modifiedAt: createdAt, entryCount: 0 }`
   - Registers device in `sync.deviceList = [{ id: crypto.randomUUID(), name: navigator.userAgentData?.platform ?? 'Unknown', lastSeen: Date.now() }]`
5. Popup transitions to main view

### 7.2 Unlock

1. Popup opens, calls `SW.isUnlocked()` → `false`
2. Popup shows `UnlockDialog`; user enters password
3. `SW.unlock(password)`:
   - Reads `local.vaultBlob`
   - Derives key with stored salt
   - `crypto.subtle.decrypt` → if fails, return `{ ok: false, error: 'wrong_password' }`
   - On success, stores `key` and `decryptedVault` in SW memory
   - Records `lastUnlockedAt`; starts auto-lock timer
4. Popup receives `{ ok: true }` → renders main view

### 7.3 Add a TOTP entry

1. User clicks `+` → `AddEntryDialog`
2. Two paths:
   - **Scan QR** — opens offscreen document, captures the active tab via `chrome.tabs.captureVisibleTab`, decodes via `qr.ts`
   - **Manual** — paste `otpauth://` URI or enter `secret`/`algorithm`/`digits`/`period`
3. Parser: `parseOtpauth(uri) → CodeEntry`
4. `SW.addEntry(entry)`:
   - Validates secret via Base32 decode test
   - Appends to `decryptedVault.codes`
   - Re-encrypts, persists `local.vaultBlob`
5. UI updates

### 7.4 Auto-fill on a website

1. User is on `example.com/login` with email/password/2FA form
2. Content script's `MutationObserver` detects 2FA input → injects inline icon
3. User clicks icon → content script sends `fill_request` to SW with `{ tabId, fieldSelector, domain }`
4. SW checks `isUnlocked()`:
   - **Unlocked:** SW looks up entries whose `issuer` or `account` matches the `domain` (case-insensitive substring match, e.g. `github.com` matches issuer `GitHub`); if exactly one match, auto-fills; if multiple, opens the popup with those entries highlighted for the user to pick; if none, opens the popup and shows "No entry for example.com — add one?"
   - **Locked:** SW responds `locked`, content script opens popup with `?action=unlock&returnTo=fill&domain=example.com`
5. Content script sets `input.value = code` and dispatches `input` + `change` events (so React / Vue / Angular state updates)
6. Content script removes the inline icon after fill
7. **Failure modes:**
   - No matching entry for domain → icon doesn't appear (silent)
   - Multiple matching entries → icon shows "?" with a small menu listing options
   - Page rejects synthetic events → fallback: copy to clipboard, show toast

### 7.5 Add/edit a note

1. Notes tab → `NotesList` → click `+` → `NoteEditor`
2. `NoteEditor` is a textarea with markdown preview tab
3. Auto-save on debounce (500 ms): `SW.saveNote({ id, title, body, updatedAt })`
4. Same encryption / persistence as codes

### 7.6 Lock

- **Manual:** Settings → Lock Now → SW zeroes `derivedKey` and `decryptedVault`
- **Auto:** Timer in SW (`setTimeout(autoLockMs)`), reset on every user action; on expiry → `SW.lock()`
- **Hard:** Browser close always locks (no persisted key)

### 7.7 Export / import `.aeropad`

- **Export:** Options → Export → optional re-encrypt with a separate password → downloads `aeropad-YYYY-MM-DD.aeropad` (JSON: `{ v, kdf: { algo, iter, salt }, iv, ciphertext, meta }`)
- **Import:** Options → Import → choose file → if encrypted, prompt for password → merges into vault (replace / merge strategy in settings)

## 8. Security Model

### 8.1 What we protect

- **At rest:** Vault is AES-256-GCM-encrypted; key derived from master password via PBKDF2-SHA256 with 600,000 iterations and a 16-byte random salt
- **In memory:** Plaintext vault lives only in service worker memory; wiped on lock, on SW death, on browser close
- **In transit:** None — extension makes zero network requests
- **CSP:** `script-src 'self'; object-src 'self'` — no remote scripts, no `eval`
- **Vendored libs:** `qr.ts` is the only third-party code, vendored locally, no CDN
- **Content script privacy:** never reads `input.value`; only injects a button and sets the value on explicit user click
- **Auto-lock:** 15 min default (configurable in options)
- **Master password:** never stored, never logged, never sent anywhere
- **No recovery:** lost password = lost vault (documented in README, matches AeroPad)

### 8.2 Threat model

| Threat | Mitigation | In scope |
|---|---|---|
| Stolen device, locked screen | Disk encryption + browser lock | ✅ |
| Browser memory dump while unlocked | Auto-lock + wipe on lock | ✅ |
| Malicious remote script in extension | Strict CSP, no CDN | ✅ |
| Network sniffing | Zero network calls | ✅ |
| Compromised master password | None (user's responsibility) | ❌ |
| Malicious extension with `storage` permission | Cannot read another extension's storage, but can read DOM | ⚠️ Mitigated: we never write to host pages except the explicit fill event |
| Phishing site mimicking real login | Out of scope (same as any 2FA app) | ❌ |

## 9. Testing Strategy

- **Unit (Vitest):** `crypto.ts`, `totp.ts`, `aeropad-format.ts`, `storage.ts`, `messages.ts` — pure functions, fast feedback
- **RFC 6238 test vectors:** official vectors from Appendix B for TOTP correctness
- **NIST AES-GCM test vectors:** from NIST CAVP for crypto correctness
- **Integration (Vitest + jsdom):** SW message handlers, popup reducers, message routing
- **E2E (Playwright with real Chrome):** load unpacked extension, run scenarios from a fixture page
- **Manual QA:** TOTP codes match Authy / Google Authenticator for 5 popular services
- **Coverage target:** ≥ 80 % lines / branches / functions per `common/testing.md`

## 10. Acceptance Criteria

1. Clean install → create vault → add 1 TOTP entry → code matches RFC 6238 vector at the expected second
2. Wrong password → "wrong password" error, no partial state
3. QR scan of `otpauth://totp/...` URI parses correctly into an entry
4. Auto-fill on a fixture page with `<input autocomplete="one-time-code">` fills the code, dispatches `input` event, doesn't reload the page
5. Note create / edit / delete round-trips through encryption; ciphertext in storage is unreadable without the password
6. Export `.aeropad` → wipe storage → import the same file → identical vault
7. Auto-lock fires after the configured timeout; unlocked state wiped
8. All 10 languages load and switch in < 100 ms
9. `npm run build` produces a `dist/` that loads cleanly as an unpacked extension in Chrome stable with no manifest warnings
10. No console errors or warnings during normal use
11. Lighthouse-style CSP check passes (no inline scripts, no eval)

## 11. Open Questions

1. **QR scanning permissions** — `chrome.tabs.captureVisibleTab` requires `<all_urls>` host permission plus user gesture; alternatives include asking the user to drag-and-drop a QR image, or paste an image. **Decision:** implement both (offscreen capture + drag-and-drop) so users on restricted pages can still add entries.
2. **Sidebar / omnibox** — deferred to v2.
3. **Firefox support** — WebExtension API differs slightly; deferred.

## 12. File Structure

```
aeropad-ext/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── manifest.json
├── README.md
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-09-02-aeropad-chrome-ext-design.md
├── src/
│   ├── popup/
│   │   ├── index.html
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── UnlockDialog.tsx
│   │   │   ├── CodeList.tsx
│   │   │   ├── CodeItem.tsx
│   │   │   ├── NotesList.tsx
│   │   │   ├── NoteEditor.tsx
│   │   │   ├── AddEntryDialog.tsx
│   │   │   └── SettingsMenu.tsx
│   │   └── styles.css
│   ├── background/
│   │   └── service-worker.ts
│   ├── content/
│   │   └── detector.ts
│   ├── options/
│   │   ├── options.html
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   └── components/
│   │       ├── ImportExport.tsx
│   │       ├── ChangePassword.tsx
│   │       ├── Devices.tsx
│   │       ├── Language.tsx
│   │       ├── AutoLock.tsx
│   │       └── SiteControls.tsx
│   ├── lib/
│   │   ├── crypto.ts
│   │   ├── totp.ts
│   │   ├── storage.ts
│   │   ├── aeropad-format.ts
│   │   ├── messages.ts
│   │   ├── i18n.ts
│   │   ├── qr.ts
│   │   └── domain-match.ts
│   ├── locales/
│   │   ├── en.json
│   │   ├── vi.json
│   │   ├── zh.json
│   │   ├── ko.json
│   │   ├── ja.json
│   │   ├── es.json
│   │   ├── id.json
│   │   ├── ar.json
│   │   ├── hi.json
│   │   └── pt.json
│   └── types/
│       └── index.ts
├── test/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── fixtures/
│       └── login-page.html
├── icons/
│   ├── 16.png
│   ├── 48.png
│   └── 128.png
└── dist/                       # build output
```

## 13. References

- Source: <https://github.com/oaichu/AeroPad> (MIT)
- RFC 6238 (TOTP): <https://datatracker.ietf.org/doc/html/rfc6238>
- OWASP Password Storage Cheat Sheet (PBKDF2 iterations): <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- Chrome Extensions Manifest V3: <https://developer.chrome.com/docs/extensions/develop/concepts/manifest-v3>
- WebCrypto API: <https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API>
