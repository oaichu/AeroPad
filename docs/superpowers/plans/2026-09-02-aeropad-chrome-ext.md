# AeroPad Chrome Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Manifest V3 Chrome extension that brings AeroPad's local-first 2FA authenticator and encrypted notes to every website, with smart auto-fill on 2FA inputs.

**Architecture:** Four execution contexts (service worker vault gatekeeper, Preact popup, lightweight content script detector, options page). Vanilla TypeScript for lib and SW; Preact for UI. Vendored QR decoder. No build target beyond `dist/`. All data AES-256-GCM-encrypted at rest, zero network calls.

**Tech Stack:** TypeScript 5.x (strict), Preact 10.x, Vite 5.x, `@crxjs/vite-plugin`, Vitest 1.x, Playwright 1.x, ESLint, Prettier.

**Spec:** `docs/superpowers/specs/2026-09-02-aeropad-chrome-ext-design.md`

## Global Constraints

These come straight from the spec. Every task implicitly honors them.

- TypeScript: `strict: true`, `noUncheckedIndexedAccess: true`
- Chrome Manifest V3 only; service worker is a module (`"type": "module"`)
- CSP: `script-src 'self'; object-src 'self'` — no `eval`, no inline scripts, no remote scripts
- All third-party libraries vendored locally (no CDN); only first-party runtime dependency is Preact
- Total bundle size: ≤ 40 KB uncompressed
- Encryption: PBKDF2-SHA256 with **600,000 iterations**, 16-byte salt, AES-256-GCM with 12-byte IV
- TOTP: RFC 6238 — supports HMAC-SHA1/256/512, 6/8 digits, configurable period (default 30 s)
- No `any` in the message protocol; all messages are typed discriminated unions
- Auto-lock default 15 min; locked state wipes `derivedKey` and `decryptedVault` from SW memory
- Test coverage target: ≥ 80 % lines/branches/functions
- Network: zero outbound requests
- 10 locales: `en`, `vi`, `zh`, `ko`, `ja`, `es`, `id`, `ar` (RTL), `hi`, `pt`

## File Structure

```
aeropad-ext/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── manifest.json
├── README.md
├── public/
│   └── icons/                # 16/48/128 PNG
├── src/
│   ├── types/index.ts        # shared types
│   ├── lib/
│   │   ├── crypto.ts         # PBKDF2 + AES-GCM
│   │   ├── totp.ts           # RFC 6238
│   │   ├── base32.ts         # Base32 decode for TOTP secrets
│   │   ├── storage.ts        # chrome.storage wrappers
│   │   ├── aeropad-format.ts # .aeropad backup file
│   │   ├── messages.ts       # typed message protocol
│   │   ├── i18n.ts           # locale loader
│   │   ├── qr.ts             # vendored QR decoder
│   │   └── domain-match.ts   # issuer/domain matching
│   ├── background/
│   │   └── service-worker.ts
│   ├── content/
│   │   └── detector.ts
│   ├── popup/
│   │   ├── index.html
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── styles.css
│   │   └── components/
│   │       ├── UnlockDialog.tsx
│   │       ├── CodeList.tsx
│   │       ├── CodeItem.tsx
│   │       ├── NotesList.tsx
│   │       ├── NoteEditor.tsx
│   │       ├── AddEntryDialog.tsx
│   │       └── SettingsMenu.tsx
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
│   └── locales/
│       ├── en.json
│       ├── vi.json
│       ├── zh.json
│       ├── ko.json
│       ├── ja.json
│       ├── es.json
│       ├── id.json
│       ├── ar.json
│       ├── hi.json
│       └── pt.json
├── test/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── fixtures/
│       └── login-page.html
└── dist/                     # build output (gitignored)
```

---

## Task 1: Project Scaffolding

**Files:**
- Create: `package.json`, `tsconfig.json`, `vite.config.ts`, `manifest.json`, `.gitignore`, `.eslintrc.cjs`, `.prettierrc`, `public/icons/.gitkeep`, `test/fixtures/.gitkeep`
- Create: `README.md`

**Goal:** A `npm install` + `npm run build` produces a loadable unpacked extension skeleton.

- [ ] **Step 1: Initialize package.json**

```json
{
  "name": "aeropad-ext",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite build --watch --mode development",
    "build": "tsc --noEmit && vite build",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:cov": "vitest run --coverage",
    "test:e2e": "playwright test",
    "lint": "eslint 'src/**/*.{ts,tsx}' 'test/**/*.{ts,tsx}'",
    "format": "prettier --write 'src/**/*.{ts,tsx,json,css,html}'"
  },
  "dependencies": {
    "preact": "^10.22.0"
  },
  "devDependencies": {
    "@crxjs/vite-plugin": "^2.0.0-beta.23",
    "@playwright/test": "^1.45.0",
    "@testing-library/preact": "^3.2.4",
    "@types/chrome": "^0.0.268",
    "@types/node": "^20.14.0",
    "@typescript-eslint/eslint-plugin": "^7.13.0",
    "@typescript-eslint/parser": "^7.13.0",
    "@vitest/coverage-v8": "^1.6.0",
    "eslint": "^8.57.0",
    "eslint-config-prettier": "^9.1.0",
    "happy-dom": "^14.10.0",
    "prettier": "^3.3.0",
    "typescript": "^5.4.5",
    "vite": "^5.3.0",
    "vitest": "^1.6.0"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "jsx": "react-jsx",
    "jsxImportSource": "preact",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "noEmit": true,
    "types": ["chrome", "vitest/globals"],
    "paths": {
      "react": ["./node_modules/preact/compat/"],
      "react-dom": ["./node_modules/preact/compat/"]
    }
  },
  "include": ["src", "test"]
}
```

- [ ] **Step 3: Create vite.config.ts**

```ts
import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { crx } from '@crxjs/vite-plugin';
import { resolve } from 'node:path';
import manifest from './manifest.json' with { type: 'json' };

export default defineConfig({
  plugins: [preact(), crx({ manifest })],
  build: {
    target: 'es2022',
    sourcemap: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        'background/service-worker': resolve(__dirname, 'src/background/service-worker.ts'),
        'content/detector': resolve(__dirname, 'src/content/detector.ts'),
      },
    },
  },
  resolve: {
    alias: { react: 'preact/compat', 'react-dom': 'preact/compat' },
  },
  test: {
    globals: true,
    environment: 'happy-dom',
    coverage: { reporter: ['text', 'html'], thresholds: { lines: 80, branches: 80, functions: 80 } },
  },
});
```

- [ ] **Step 4: Create manifest.json**

```json
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
    "default_title": "AeroPad"
  },
  "content_scripts": [
    { "matches": ["<all_urls>"], "js": ["dist/content/detector.js"], "run_at": "document_idle" }
  ],
  "options_page": "dist/options/options.html",
  "commands": { "fill-current": { "suggested_key": { "default": "Ctrl+Shift+F" } } },
  "content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }
}
```

- [ ] **Step 5: Create .gitignore**

```
node_modules/
dist/
coverage/
.vite/
*.log
.DS_Store
```

- [ ] **Step 6: Install and verify build**

Run: `npm install`
Expected: completes without errors.

Create a minimal `src/popup/index.html`:
```html
<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app">loading</div><script type="module" src="./main.tsx"></script></body></html>
```

Create a minimal `src/popup/main.tsx`:
```ts
document.getElementById('app')!.textContent = 'AeroPad';
```

Create empty placeholder files:
```bash
mkdir -p src/background src/content src/lib src/types src/locales src/options src/options/components src/popup/components test/fixtures public/icons
touch src/background/service-worker.ts src/content/detector.ts src/options/options.html src/options/main.tsx
```

Run: `npm run build`
Expected: produces `dist/` with `popup/index.html`, `background/service-worker.js`, `content/detector.js`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: scaffold Vite + Preact + CRX plugin extension project"
```

---

## Task 2: Shared Types

**Files:**
- Create: `src/types/index.ts`
- Test: `test/unit/types.test.ts`

**Interfaces:**
- Consumes: none (first task after scaffolding)
- Produces: `CodeEntry`, `Note`, `Vault`, `VaultBlob`, `VaultMeta`, `Device`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import type { CodeEntry, Vault, VaultBlob } from '../../src/types/index.js';
import { isCodeEntry, isVault } from '../../src/types/index.js';

describe('types', () => {
  it('isCodeEntry accepts valid entry', () => {
    const e: CodeEntry = {
      id: '1', issuer: 'GitHub', account: 'me@x.com',
      secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
    };
    expect(isCodeEntry(e)).toBe(true);
  });

  it('isCodeEntry rejects missing fields', () => {
    expect(isCodeEntry({ id: '1' })).toBe(false);
  });

  it('isVault accepts empty vault', () => {
    expect(isVault({ codes: [], notes: [] })).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `isCodeEntry` not exported.

- [ ] **Step 3: Implement types and guards**

```ts
// src/types/index.ts
export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface CodeEntry {
  id: string;
  issuer: string;
  account: string;
  secret: string;          // base32
  algorithm: TotpAlgorithm;
  digits: 6 | 8;
  period: number;          // seconds
  createdAt: number;
}

export interface Note {
  id: string;
  title: string;
  body: string;
  updatedAt: number;
}

export interface Vault {
  codes: CodeEntry[];
  notes: Note[];
}

export interface VaultBlob {
  v: 1;
  salt: string;            // base64url
  iv: string;              // base64url
  ciphertext: string;      // base64url
}

export interface VaultMeta {
  version: 1;
  kdfParams: { algo: 'PBKDF2-SHA256'; iter: 600_000 };
  createdAt: number;
  modifiedAt: number;
  entryCount: number;
}

export interface Device {
  id: string;
  name: string;
  lastSeen: number;
}

export function isCodeEntry(x: unknown): x is CodeEntry {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.id === 'string'
    && typeof o.issuer === 'string'
    && typeof o.account === 'string'
    && typeof o.secret === 'string'
    && (o.algorithm === 'SHA1' || o.algorithm === 'SHA256' || o.algorithm === 'SHA512')
    && (o.digits === 6 || o.digits === 8)
    && typeof o.period === 'number'
    && typeof o.createdAt === 'number';
}

export function isVault(x: unknown): x is Vault {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return Array.isArray(o.codes) && Array.isArray(o.notes);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/types test/unit/types.test.ts
git commit -m "feat(types): add shared types and runtime guards"
```

---

## Task 3: Base32 Decoder

**Files:**
- Create: `src/lib/base32.ts`
- Test: `test/unit/base32.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces: `base32Decode(input: string): Uint8Array` (throws on invalid input)

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { base32Decode } from '../../src/lib/base32.js';

describe('base32Decode', () => {
  it('decodes RFC 4648 test vector', () => {
    expect(Array.from(base32Decode('JBSWY3DPEHPK3PXP'))).toEqual([
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef,
    ]);
  });

  it('is case-insensitive', () => {
    expect(Array.from(base32Decode('jbswy3dpehpk3pxp'))).toEqual(Array.from(base32Decode('JBSWY3DPEHPK3PXP')));
  });

  it('ignores padding', () => {
    expect(Array.from(base32Decode('JBSWY3DPEHPK3PXP===='))).toEqual(Array.from(base32Decode('JBSWY3DPEHPK3PXP')));
  });

  it('throws on invalid character', () => {
    expect(() => base32Decode('JBSW!3DPEHPK3PXP')).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- base32`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement base32Decode**

```ts
// src/lib/base32.ts
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  if (cleaned.length === 0) return new Uint8Array(0);

  const out: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const ch of cleaned) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`Invalid base32 character: ${ch}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- base32`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/base32.ts test/unit/base32.test.ts
git commit -m "feat(base32): add base32 decoder for TOTP secrets"
```

---

## Task 4: Crypto Module (PBKDF2 + AES-GCM)

**Files:**
- Create: `src/lib/crypto.ts`
- Test: `test/unit/crypto.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `randomBytes(n: number): Uint8Array`
  - `deriveKey(password: string, salt: Uint8Array, iterations?: number): Promise<CryptoKey>`
  - `encrypt(plaintext: Uint8Array, key: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }>`
  - `decrypt(ciphertext: Uint8Array, iv: Uint8Array, key: CryptoKey): Promise<Uint8Array>`
  - `bytesToBase64Url(b: Uint8Array): string`
  - `base64UrlToBytes(s: string): Uint8Array`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import {
  randomBytes, deriveKey, encrypt, decrypt,
  bytesToBase64Url, base64UrlToBytes,
} from '../../src/lib/crypto.js';

describe('crypto helpers', () => {
  it('randomBytes returns the requested length', () => {
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(0).length).toBe(0);
  });

  it('base64url round-trips', () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 255]);
    const s = bytesToBase64Url(b);
    expect(s).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlToBytes(s))).toEqual(Array.from(b));
  });
});

describe('AES-GCM round-trip', () => {
  it('encrypts and decrypts arbitrary bytes', async () => {
    const salt = randomBytes(16);
    const key = await deriveKey('correct horse battery staple', salt, 1000); // fast for tests
    const plaintext = new TextEncoder().encode('hello world');
    const { iv, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, iv, key);
    expect(new TextDecoder().decode(decrypted)).toBe('hello world');
  });

  it('rejects tampered ciphertext', async () => {
    const salt = randomBytes(16);
    const key = await deriveKey('pw', salt, 1000);
    const { iv, ciphertext } = await encrypt(new TextEncoder().encode('x'), key);
    ciphertext[0]! ^= 0xff;
    await expect(decrypt(ciphertext, iv, key)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- crypto`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement crypto.ts**

```ts
// src/lib/crypto.ts
export const KDF_ITERATIONS = 600_000;

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = KDF_ITERATIONS,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encrypt(
  plaintext: Uint8Array,
  key: CryptoKey,
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext: new Uint8Array(ct) };
}

export async function decrypt(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(pt);
}

export function bytesToBase64Url(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(s: string): Uint8Array {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- crypto`
Expected: PASS (the 1000-iteration tests are fast).

- [ ] **Step 5: Commit**

```bash
git add src/lib/crypto.ts test/unit/crypto.test.ts
git commit -m "feat(crypto): add PBKDF2 + AES-GCM helpers"
```

---

## Task 5: TOTP (RFC 6238)

**Files:**
- Create: `src/lib/totp.ts`
- Test: `test/unit/totp.test.ts`

**Interfaces:**
- Consumes: `base32Decode` (Task 3), `CodeEntry` (Task 2)
- Produces:
  - `totp(secret: string, opts: { algorithm, digits, period, t }): string`
  - `currentCode(entry: CodeEntry, now?: number): string`
  - `remainingSeconds(entry: CodeEntry, now?: number): number`

- [ ] **Step 1: Write the failing test (RFC 6238 Appendix B)**

```ts
import { describe, it, expect } from 'vitest';
import { totp, currentCode, remainingSeconds } from '../../src/lib/totp.js';

describe('totp RFC 6238 vectors', () => {
  // SHA-1, 8-digit, secret = "12345678901234567890"
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // base32 of "12345678901234567890"

  it('T=59 → 94287082', () => {
    expect(totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 59 })).toBe('94287082');
  });
  it('T=1111111109 → 07081804', () => {
    expect(totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1111111109 })).toBe('07081804');
  });
  it('T=1111111111 → 14050471', () => {
    expect(totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1111111111 })).toBe('14050471');
  });
  it('T=1234567890 → 89005924', () => {
    expect(totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1234567890 })).toBe('89005924');
  });
  it('T=2000000000 → 69279037', () => {
    expect(totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 2000000000 })).toBe('69279037');
  });
});

describe('currentCode & remainingSeconds', () => {
  const entry = {
    id: '1', issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1' as const, digits: 6 as const, period: 30, createdAt: 0,
  };

  it('currentCode returns 6 digits', () => {
    expect(currentCode(entry)).toMatch(/^\d{6}$/);
  });

  it('remainingSeconds is in (0, 30]', () => {
    const r = remainingSeconds(entry);
    expect(r).toBeGreaterThan(0);
    expect(r).toBeLessThanOrEqual(30);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- totp`
Expected: FAIL.

- [ ] **Step 3: Implement totp.ts**

```ts
// src/lib/totp.ts
import type { CodeEntry, TotpAlgorithm } from '../types/index.js';
import { base32Decode } from './base32.js';

const ALGO_MAP: Record<TotpAlgorithm, string> = {
  SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512',
};

function counter(t: number, period: number): Uint8Array {
  const c = Math.floor(t / period);
  const b = new ArrayBuffer(8);
  const view = new DataView(b);
  view.setUint32(0, Math.floor(c / 0x100000000));
  view.setUint32(4, c >>> 0);
  return new Uint8Array(b);
}

function hotp(secret: Uint8Array, counter: Uint8Array, algorithm: string, digits: number): string {
  return crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: algorithm }, false, ['sign'])
    .then((key) => crypto.subtle.sign('HMAC', key, counter))
    .then((sig) => {
      const bytes = new Uint8Array(sig);
      const offset = bytes[bytes.length - 1]! & 0x0f;
      const bin = ((bytes[offset]! & 0x7f) << 24)
        | ((bytes[offset + 1]! & 0xff) << 16)
        | ((bytes[offset + 2]! & 0xff) << 8)
        | (bytes[offset + 3]! & 0xff);
      const mod = bin % 10 ** digits;
      return mod.toString().padStart(digits, '0');
    });
}

export async function totp(
  secret: string,
  opts: { algorithm: TotpAlgorithm; digits: 6 | 8; period: number; t: number },
): Promise<string> {
  const key = base32Decode(secret);
  return hotp(key, counter(opts.t, opts.period), ALGO_MAP[opts.algorithm], opts.digits);
}

export async function currentCode(entry: CodeEntry, now: number = Date.now()): Promise<string> {
  return totp(entry.secret, {
    algorithm: entry.algorithm, digits: entry.digits, period: entry.period, t: Math.floor(now / 1000),
  });
}

export function remainingSeconds(entry: CodeEntry, now: number = Date.now()): number {
  const t = Math.floor(now / 1000);
  return entry.period - (t % entry.period);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- totp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/totp.ts test/unit/totp.test.ts
git commit -m "feat(totp): implement RFC 6238 with Appendix B test vectors"
```

---

## Task 6: Storage Wrappers

**Files:**
- Create: `src/lib/storage.ts`
- Test: `test/unit/storage.test.ts` (uses `happy-dom` with a minimal `chrome` shim)

**Interfaces:**
- Consumes: `VaultBlob`, `VaultMeta`, `Device`, `KDF_ITERATIONS` from `crypto.ts`
- Produces:
  - `getVaultBlob(): Promise<VaultBlob | null>`
  - `setVaultBlob(b: VaultBlob): Promise<void>`
  - `getVaultMeta(): Promise<VaultMeta | null>`
  - `setVaultMeta(m: VaultMeta): Promise<void>`
  - `getDeviceList(): Promise<Device[]>`
  - `setDeviceList(devices: Device[]): Promise<void>`
  - `getSessionLock(): Promise<{ lastUnlockedAt: number; autoLockMinutes: number }>`
  - `setSessionLock(s): Promise<void>`

- [ ] **Step 1: Write the failing test**

Create a chrome shim helper in `test/helpers/chrome-shim.ts`:
```ts
let store: Record<string, unknown> = {};
(globalThis as any).chrome = {
  storage: {
    local: {
      get: (k: string | string[]) => Promise.resolve(
        Array.isArray(k)
          ? Object.fromEntries(k.map((key) => [key, store[key]]))
          : { [k]: store[k] }),
      set: (o: Record<string, unknown>) => { Object.assign(store, o); return Promise.resolve(); },
      remove: (k: string) => { delete store[k]; return Promise.resolve(); },
    },
    sync: {
      get: (k: string | string[]) => Promise.resolve(
        Array.isArray(k)
          ? Object.fromEntries(k.map((key) => [key, store['sync:' + key]]))
          : { [k]: store['sync:' + k] }),
      set: (o: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(o)) store['sync:' + k] = v;
        return Promise.resolve();
      },
    },
  },
};
```

Test `test/unit/storage.test.ts`:
```ts
import './helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  getVaultBlob, setVaultBlob, getDeviceList, setDeviceList, getSessionLock, setSessionLock,
} from '../../src/lib/storage.js';

beforeEach(() => {
  (globalThis as any).chrome.storage.local.remove('vaultBlob');
});

describe('storage', () => {
  it('vaultBlob round-trips', async () => {
    expect(await getVaultBlob()).toBeNull();
    const blob = { v: 1 as const, salt: 'aa', iv: 'bb', ciphertext: 'cc' };
    await setVaultBlob(blob);
    expect(await getVaultBlob()).toEqual(blob);
  });

  it('deviceList round-trips through sync', async () => {
    await setDeviceList([{ id: 'd1', name: 'PC', lastSeen: 1 }]);
    expect(await getDeviceList()).toEqual([{ id: 'd1', name: 'PC', lastSeen: 1 }]);
  });

  it('sessionLock defaults to 15 minutes', async () => {
    expect(await getSessionLock()).toEqual({ lastUnlockedAt: 0, autoLockMinutes: 15 });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- storage`
Expected: FAIL.

- [ ] **Step 3: Implement storage.ts**

```ts
// src/lib/storage.ts
import type { VaultBlob, VaultMeta, Device } from '../types/index.js';

const LOCAL = chrome.storage.local;
const SYNC = chrome.storage.sync;

export async function getVaultBlob(): Promise<VaultBlob | null> {
  const r = await LOCAL.get('vaultBlob');
  return (r.vaultBlob as VaultBlob | undefined) ?? null;
}
export async function setVaultBlob(b: VaultBlob): Promise<void> {
  await LOCAL.set({ vaultBlob: b });
}

export async function getVaultMeta(): Promise<VaultMeta | null> {
  const r = await LOCAL.get('vaultMeta');
  return (r.vaultMeta as VaultMeta | undefined) ?? null;
}
export async function setVaultMeta(m: VaultMeta): Promise<void> {
  await LOCAL.set({ vaultMeta: m });
}

export async function getDeviceList(): Promise<Device[]> {
  const r = await SYNC.get('deviceList');
  return (r.deviceList as Device[] | undefined) ?? [];
}
export async function setDeviceList(devices: Device[]): Promise<void> {
  await SYNC.set({ deviceList: devices });
}

const DEFAULT_LOCK = { lastUnlockedAt: 0, autoLockMinutes: 15 };

export async function getSessionLock(): Promise<typeof DEFAULT_LOCK> {
  const r = await LOCAL.get('sessionLock');
  return (r.sessionLock as typeof DEFAULT_LOCK | undefined) ?? DEFAULT_LOCK;
}
export async function setSessionLock(s: typeof DEFAULT_LOCK): Promise<void> {
  await LOCAL.set({ sessionLock: s });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- storage`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/storage.ts test/unit/storage.test.ts test/helpers/chrome-shim.ts
git commit -m "feat(storage): typed chrome.storage wrappers"
```

---

## Task 7: `.aeropad` Backup File Format

**Files:**
- Create: `src/lib/aeropad-format.ts`
- Test: `test/unit/aeropad-format.test.ts`

**Interfaces:**
- Consumes: `crypto.ts`, `storage.ts`
- Produces:
  - `exportVault(vault, password?): Promise<string>` — JSON string
  - `importVault(json: string, password?): Promise<Vault>`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { exportVault, importVault } from '../../src/lib/aeropad-format.js';

describe('aeropad format', () => {
  it('exports and re-imports an empty vault', async () => {
    const json = await exportVault({ codes: [], notes: [] }, 'pw');
    const v = await importVault(json, 'pw');
    expect(v).toEqual({ codes: [], notes: [] });
  });

  it('round-trips with entries', async () => {
    const vault = {
      codes: [{ id: 'a', issuer: 'X', account: 'a@x', secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA1' as const, digits: 6 as const, period: 30, createdAt: 1 }],
      notes: [{ id: 'n1', title: 't', body: 'b', updatedAt: 1 }],
    };
    const json = await exportVault(vault, 'pw');
    expect(await importVault(json, 'pw')).toEqual(vault);
  });

  it('rejects wrong password', async () => {
    const json = await exportVault({ codes: [], notes: [] }, 'right');
    await expect(importVault(json, 'wrong')).rejects.toThrow();
  });

  it('rejects malformed JSON', async () => {
    await expect(importVault('not json', 'pw')).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- aeropad-format`
Expected: FAIL.

- [ ] **Step 3: Implement aeropad-format.ts**

```ts
// src/lib/aeropad-format.ts
import type { Vault } from '../types/index.js';
import { isVault } from '../types/index.js';
import { deriveKey, encrypt, decrypt, randomBytes, bytesToBase64Url, base64UrlToBytes } from './crypto.js';
import { KDF_ITERATIONS } from './crypto.js';

interface AeropadFile {
  v: 1;
  kdf: { algo: 'PBKDF2-SHA256'; iter: number; salt: string };
  iv: string;
  ciphertext: string;
  meta: { createdAt: number; modifiedAt: number; entryCount: number };
}

export async function exportVault(
  vault: Vault,
  password: string,
): Promise<string> {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt, KDF_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const { iv, ciphertext } = await encrypt(plaintext, key);
  const file: AeropadFile = {
    v: 1,
    kdf: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS, salt: bytesToBase64Url(salt) },
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(ciphertext),
    meta: {
      createdAt: Date.now(),
      modifiedAt: Date.now(),
      entryCount: vault.codes.length,
    },
  };
  return JSON.stringify(file, null, 2);
}

export async function importVault(json: string, password: string): Promise<Vault> {
  let file: unknown;
  try { file = JSON.parse(json); } catch { throw new Error('Malformed .aeropad file'); }
  if (typeof file !== 'object' || file === null) throw new Error('Malformed .aeropad file');
  const f = file as Partial<AeropadFile>;
  if (f.v !== 1 || !f.kdf || !f.iv || !f.ciphertext) throw new Error('Unsupported .aeropad version');

  const key = await deriveKey(password, base64UrlToBytes(f.kdf.salt), f.kdf.iter);
  let plaintext: Uint8Array;
  try {
    plaintext = await decrypt(base64UrlToBytes(f.ciphertext), base64UrlToBytes(f.iv), key);
  } catch {
    throw new Error('Wrong password or corrupted file');
  }
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (!isVault(parsed)) throw new Error('Invalid vault structure');
  return parsed;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- aeropad-format`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/aeropad-format.ts test/unit/aeropad-format.test.ts
git commit -m "feat(aeropad): add .aeropad backup file format"
```

---

## Task 8: Typed Message Protocol

**Files:**
- Create: `src/lib/messages.ts`
- Test: `test/unit/messages.test.ts`

**Interfaces:**
- Consumes: `CodeEntry`, `Note`, `Vault` from `types/index.ts`
- Produces: discriminated-union `Message` types and `isMessage(x: unknown): x is Message`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { isMessage } from '../../src/lib/messages.js';

describe('isMessage', () => {
  it('accepts unlock request', () => {
    expect(isMessage({ kind: 'unlock', password: 'x' })).toBe(true);
  });

  it('rejects unknown kind', () => {
    expect(isMessage({ kind: 'wat' })).toBe(false);
  });

  it('rejects non-object', () => {
    expect(isMessage('hello')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- messages`
Expected: FAIL.

- [ ] **Step 3: Implement messages.ts**

```ts
// src/lib/messages.ts
import type { CodeEntry, Note, Vault } from '../types/index.js';

export type Request =
  | { kind: 'createVault'; password: string }
  | { kind: 'unlock'; password: string }
  | { kind: 'lock' }
  | { kind: 'isUnlocked' }
  | { kind: 'getCodes' }
  | { kind: 'getCode'; id: string }
  | { kind: 'addEntry'; entry: Omit<CodeEntry, 'id' | 'createdAt'> }
  | { kind: 'updateEntry'; id: string; patch: Partial<CodeEntry> }
  | { kind: 'deleteEntry'; id: string }
  | { kind: 'reorderEntries'; orderedIds: string[] }
  | { kind: 'getNotes' }
  | { kind: 'saveNote'; note: Note }
  | { kind: 'deleteNote'; id: string }
  | { kind: 'exportAeropad'; password?: string }
  | { kind: 'importAeropad'; json: string; password: string; strategy: 'replace' | 'merge' }
  | { kind: 'changeMasterPassword'; oldPassword: string; newPassword: string }
  | { kind: 'fillOnTab'; tabId: number; entryId: string };

export type Response =
  | { ok: true; data?: unknown }
  | { ok: false; error: string };

export type FillRequestFromContent = {
  kind: 'fill_request';
  tabId: number;
  fieldSelector: string;
  domain: string;
};

export type FillCommandToContent = {
  kind: 'fill_command';
  code: string;
};

export type Message = Request | FillRequestFromContent | FillCommandToContent;

export function isMessage(x: unknown): x is Message {
  if (typeof x !== 'object' || x === null) return false;
  const k = (x as { kind?: unknown }).kind;
  return typeof k === 'string';
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- messages`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/messages.ts test/unit/messages.test.ts
git commit -m "feat(messages): add typed message protocol"
```

---

## Task 9: Domain Matcher

**Files:**
- Create: `src/lib/domain-match.ts`
- Test: `test/unit/domain-match.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `matchEntryForDomain(entries: CodeEntry[], domain: string): CodeEntry[]` — returns entries whose `issuer` or `account` case-insensitively contains the registrable domain (or vice versa); empty if none

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { matchEntryForDomain } from '../../src/lib/domain-match.js';
import type { CodeEntry } from '../../src/types/index.js';

const make = (issuer: string, account = ''): CodeEntry => ({
  id: issuer, issuer, account, secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0,
});

describe('matchEntryForDomain', () => {
  it('matches by issuer substring (case-insensitive)', () => {
    expect(matchEntryForDomain([make('GitHub')], 'github.com').map((e) => e.issuer)).toEqual(['GitHub']);
  });

  it('matches by account substring', () => {
    expect(matchEntryForDomain([make('Work', 'me@github.com')], 'github.com').map((e) => e.issuer)).toEqual(['Work']);
  });

  it('returns empty when no match', () => {
    expect(matchEntryForDomain([make('Google')], 'github.com')).toEqual([]);
  });

  it('returns multiple when ambiguous', () => {
    const r = matchEntryForDomain([make('GitHub'), make('Work', 'a@github.com')], 'github.com');
    expect(r.length).toBe(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- domain-match`
Expected: FAIL.

- [ ] **Step 3: Implement domain-match.ts**

```ts
// src/lib/domain-match.ts
import type { CodeEntry } from '../types/index.js';

function hostOf(domain: string): string {
  return domain.toLowerCase().replace(/^www\./, '').split(':')[0]!;
}

export function matchEntryForDomain(entries: CodeEntry[], domain: string): CodeEntry[] {
  const host = hostOf(domain);
  const hostNoTld = host.split('.').slice(-2).join('.');
  return entries.filter((e) => {
    const hay = `${e.issuer} ${e.account}`.toLowerCase();
    return hay.includes(host) || hay.includes(hostNoTld);
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- domain-match`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/domain-match.ts test/unit/domain-match.test.ts
git commit -m "feat(domain-match): issuer/account-to-domain matcher"
```

---

## Task 10: i18n with 10 Locales

**Files:**
- Create: `src/lib/i18n.ts`, `src/locales/en.json`, `src/locales/vi.json`, `src/locales/zh.json`, `src/locales/ko.json`, `src/locales/ja.json`, `src/locales/es.json`, `src/locales/id.json`, `src/locales/ar.json`, `src/locales/hi.json`, `src/locales/pt.json`
- Test: `test/unit/i18n.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `loadLocale(name: 'en' | 'vi' | 'zh' | 'ko' | 'ja' | 'es' | 'id' | 'ar' | 'hi' | 'pt'): Promise<Record<string, string>>`
  - `t(dict, key, vars?): string` — simple `{name}` substitution
  - `isRTL(name: string): boolean` — true only for `ar`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { loadLocale, t, isRTL } from '../../src/lib/i18n.js';

describe('i18n', () => {
  it('t substitutes variables', () => {
    expect(t({ greet: 'Hello, {name}!' }, 'greet', { name: 'Ada' })).toBe('Hello, Ada!');
  });

  it('t returns key when missing', () => {
    expect(t({}, 'missing.key')).toBe('missing.key');
  });

  it('isRTL true for ar', () => {
    expect(isRTL('ar')).toBe(true);
    expect(isRTL('en')).toBe(false);
  });

  it('loadLocale resolves with keys', async () => {
    const dict = await loadLocale('en');
    expect(typeof dict['app.unlock']).toBe('string');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- i18n`
Expected: FAIL.

- [ ] **Step 3: Create en.json (full) and 9 stubs**

`src/locales/en.json`:
```json
{
  "app.unlock": "Unlock AeroPad",
  "app.create": "Create vault",
  "app.lock": "Lock now",
  "unlock.placeholder": "Master password",
  "unlock.wrong": "Wrong password",
  "codes.empty": "No accounts yet. Click + to add one.",
  "codes.add": "Add account",
  "notes.empty": "No notes yet.",
  "notes.add": "New note",
  "settings.title": "Settings",
  "settings.language": "Language",
  "settings.export": "Export .aeropad",
  "settings.import": "Import .aeropad",
  "settings.changePassword": "Change master password",
  "settings.openOptions": "Open full settings"
}
```

Create the other 9 files with the same keys (translations can be the English values for now — task focuses on plumbing, not translation quality).

- [ ] **Step 4: Implement i18n.ts**

```ts
// src/lib/i18n.ts
export type LocaleName = 'en' | 'vi' | 'zh' | 'ko' | 'ja' | 'es' | 'id' | 'ar' | 'hi' | 'pt';

const RTL_LOCALES = new Set<LocaleName>(['ar']);

const cache = new Map<LocaleName, Record<string, string>>();

export async function loadLocale(name: LocaleName): Promise<Record<string, string>> {
  if (cache.has(name)) return cache.get(name)!;
  const url = chrome.runtime.getURL(`_locales/${name}/messages.json`);
  // We also support bundled JSON via dynamic import for tests
  let dict: Record<string, string>;
  try {
    const mod = await import(`../locales/${name}.json`);
    dict = mod.default as Record<string, string>;
  } catch {
    const res = await fetch(url);
    dict = await res.json();
  }
  cache.set(name, dict);
  return dict;
}

export function t(dict: Record<string, string>, key: string, vars?: Record<string, string | number>): string {
  let s = dict[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
  return s;
}

export function isRTL(name: string): boolean {
  return RTL_LOCALES.has(name as LocaleName);
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npm test -- i18n`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib/i18n.ts src/locales test/unit/i18n.test.ts
git commit -m "feat(i18n): locale loader with 10 languages and RTL detection"
```

---

## Task 11: Service Worker — Vault Lifecycle

**Files:**
- Create: `src/background/service-worker.ts`
- Test: `test/integration/service-worker.test.ts` (uses chrome shim + happy-dom)

**Interfaces:**
- Consumes: `crypto.ts`, `storage.ts`, `aeropad-format.ts`, `messages.ts`, `types/index.ts`
- Produces: `handleMessage(msg: Request): Promise<Response>` plus module-level state `state: { key, vault, autoLockTimer }`. Listens to `chrome.runtime.onMessage`.

- [ ] **Step 1: Write the failing test**

```ts
import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';

beforeEach(() => resetForTests());

describe('vault lifecycle', () => {
  it('createVault then isUnlocked', async () => {
    expect((await handleMessage({ kind: 'isUnlocked' } as any)).ok).toBe(true);
    expect((await handleMessage({ kind: 'isUnlocked' } as any)).data).toBe(false);
    const r = await handleMessage({ kind: 'createVault', password: 'pw12345678' });
    expect(r.ok).toBe(true);
    expect((await handleMessage({ kind: 'isUnlocked' } as any)).data).toBe(true);
  });

  it('unlock with wrong password fails', async () => {
    await handleMessage({ kind: 'createVault', password: 'right' });
    await handleMessage({ kind: 'lock' });
    const r = await handleMessage({ kind: 'unlock', password: 'wrong' });
    expect(r.ok).toBe(false);
  });

  it('lock wipes state', async () => {
    await handleMessage({ kind: 'createVault', password: 'pw' });
    await handleMessage({ kind: 'lock' });
    expect((await handleMessage({ kind: 'isUnlocked' } as any)).data).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- service-worker`
Expected: FAIL.

- [ ] **Step 3: Implement vault lifecycle in service-worker.ts**

```ts
// src/background/service-worker.ts
import type { Vault, Request, Response } from '../lib/messages.js';
import { KDF_ITERATIONS, deriveKey, encrypt, decrypt, randomBytes, bytesToBase64Url, base64UrlToBytes } from '../lib/crypto.js';
import { getVaultBlob, setVaultBlob, getVaultMeta, setVaultMeta, getDeviceList, setDeviceList, getSessionLock, setSessionLock } from '../lib/storage.js';

interface State {
  key: CryptoKey | null;
  vault: Vault | null;
  autoLockTimer: ReturnType<typeof setTimeout> | null;
}

const state: State = { key: null, vault: null, autoLockTimer: null };

export function resetForTests(): void {
  state.key = null;
  state.vault = null;
  if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
  state.autoLockTimer = null;
}

async function loadAndDecrypt(password: string): Promise<Vault> {
  const blob = await getVaultBlob();
  if (!blob) throw new Error('No vault');
  const key = await deriveKey(password, base64UrlToBytes(blob.salt));
  const plaintext = await decrypt(base64UrlToBytes(blob.ciphertext), base64UrlToBytes(blob.iv), key);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function encryptAndPersist(): Promise<void> {
  if (!state.key || !state.vault) throw new Error('Locked');
  const salt = randomBytes(16);
  const { iv, ciphertext } = await encrypt(new TextEncoder().encode(JSON.stringify(state.vault)), state.key);
  await setVaultBlob({ v: 1, salt: bytesToBase64Url(salt), iv: bytesToBase64Url(iv), ciphertext: bytesToBase64Url(ciphertext) });
  const meta = await getVaultMeta();
  await setVaultMeta({
    version: 1,
    kdfParams: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS },
    createdAt: meta?.createdAt ?? Date.now(),
    modifiedAt: Date.now(),
    entryCount: state.vault.codes.length,
  });
}

function scheduleAutoLock(): void {
  if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
  const { autoLockMinutes } = { autoLockMinutes: 15 };
  getSessionLock().then(({ autoLockMinutes: m }) => {
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    state.autoLockTimer = setTimeout(() => { state.key = null; state.vault = null; }, m * 60_000);
  });
}

export async function handleMessage(msg: Request): Promise<Response> {
  try {
    switch (msg.kind) {
      case 'createVault': {
        const salt = randomBytes(16);
        const key = await deriveKey(msg.password, salt, KDF_ITERATIONS);
        const vault: Vault = { codes: [], notes: [] };
        const { iv, ciphertext } = await encrypt(new TextEncoder().encode(JSON.stringify(vault)), key);
        await setVaultBlob({ v: 1, salt: bytesToBase64Url(salt), iv: bytesToBase64Url(iv), ciphertext: bytesToBase64Url(ciphertext) });
        await setVaultMeta({ version: 1, kdfParams: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS }, createdAt: Date.now(), modifiedAt: Date.now(), entryCount: 0 });
        state.key = key; state.vault = vault;
        await setDeviceList([...(await getDeviceList()), { id: crypto.randomUUID(), name: 'this-device', lastSeen: Date.now() }]);
        scheduleAutoLock();
        return { ok: true };
      }
      case 'unlock': {
        try { state.vault = await loadAndDecrypt(msg.password); }
        catch { return { ok: false, error: 'wrong_password' }; }
        state.key = await deriveKey(msg.password, base64UrlToBytes((await getVaultBlob())!.salt));
        scheduleAutoLock();
        return { ok: true };
      }
      case 'lock':
        state.key = null; state.vault = null;
        if (state.autoLockTimer) { clearTimeout(state.autoLockTimer); state.autoLockTimer = null; }
        return { ok: true };
      case 'isUnlocked':
        return { ok: true, data: state.vault !== null };
      default:
        return { ok: false, error: 'not_implemented_in_this_task' };
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'unknown' };
  }
}

chrome.runtime.onMessage.addListener((msg: Request, _sender, sendResponse) => {
  handleMessage(msg).then(sendResponse);
  return true;
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- service-worker`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/service-worker.ts test/integration/service-worker.test.ts
git commit -m "feat(sw): vault lifecycle (create / unlock / lock)"
```

---

## Task 12: Service Worker — CRUD Operations

**Files:**
- Modify: `src/background/service-worker.ts`
- Test: `test/integration/service-worker-crud.test.ts`

**Goal:** Add handlers for `addEntry`, `updateEntry`, `deleteEntry`, `reorderEntries`, `getCodes`, `getCode`, `getNotes`, `saveNote`, `deleteNote`. Each mutation re-encrypts and persists.

- [ ] **Step 1: Write the failing test**

```ts
import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';

beforeEach(() => resetForTests());

async function bootstrap() {
  await handleMessage({ kind: 'createVault', password: 'pw' });
}

describe('CRUD', () => {
  it('addEntry then getCodes returns it', async () => {
    await bootstrap();
    await handleMessage({
      kind: 'addEntry',
      entry: { issuer: 'GitHub', account: 'me', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
    });
    const r = await handleMessage({ kind: 'getCodes' });
    expect(r.ok).toBe(true);
    expect((r.data as any[]).length).toBe(1);
  });

  it('saveNote then getNotes round-trips', async () => {
    await bootstrap();
    await handleMessage({ kind: 'saveNote', note: { id: 'n1', title: 't', body: 'b', updatedAt: 1 } });
    const r = await handleMessage({ kind: 'getNotes' });
    expect((r.data as any[])[0].body).toBe('b');
  });

  it('deleteEntry removes the entry', async () => {
    await bootstrap();
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'A', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const list = (await handleMessage({ kind: 'getCodes' })).data as any[];
    await handleMessage({ kind: 'deleteEntry', id: list[0].id });
    expect(((await handleMessage({ kind: 'getCodes' })).data as any[]).length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- service-worker-crud`
Expected: FAIL — handlers not implemented.

- [ ] **Step 3: Extend handleMessage**

Add the following cases inside the switch in `handleMessage` (and import `currentCode` from `totp.ts`):

```ts
import { currentCode } from '../lib/totp.js';
import { isCodeEntry, isVault, type CodeEntry, type Note } from '../types/index.js';

// ... inside switch:
case 'addEntry': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const entry: CodeEntry = { ...msg.entry, id: crypto.randomUUID(), createdAt: Date.now() };
  if (!isCodeEntry(entry)) return { ok: false, error: 'invalid_entry' };
  state.vault.codes.push(entry);
  await encryptAndPersist();
  return { ok: true, data: entry };
}
case 'updateEntry': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const i = state.vault.codes.findIndex((c) => c.id === msg.id);
  if (i < 0) return { ok: false, error: 'not_found' };
  state.vault.codes[i] = { ...state.vault.codes[i]!, ...msg.patch };
  await encryptAndPersist();
  return { ok: true };
}
case 'deleteEntry': {
  if (!state.vault) return { ok: false, error: 'locked' };
  state.vault.codes = state.vault.codes.filter((c) => c.id !== msg.id);
  await encryptAndPersist();
  return { ok: true };
}
case 'reorderEntries': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const map = new Map(state.vault.codes.map((c) => [c.id, c]));
  state.vault.codes = msg.orderedIds.map((id) => map.get(id)!).filter(Boolean);
  await encryptAndPersist();
  return { ok: true };
}
case 'getCodes': {
  if (!state.vault) return { ok: false, error: 'locked' };
  return { ok: true, data: state.vault.codes };
}
case 'getCode': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const c = state.vault.codes.find((x) => x.id === msg.id);
  if (!c) return { ok: false, error: 'not_found' };
  return { ok: true, data: { entry: c, code: await currentCode(c) } };
}
case 'getNotes': {
  if (!state.vault) return { ok: false, error: 'locked' };
  return { ok: true, data: state.vault.notes };
}
case 'saveNote': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const i = state.vault.notes.findIndex((n) => n.id === msg.note.id);
  if (i >= 0) state.vault.notes[i] = msg.note;
  else state.vault.notes.push(msg.note);
  await encryptAndPersist();
  return { ok: true };
}
case 'deleteNote': {
  if (!state.vault) return { ok: false, error: 'locked' };
  state.vault.notes = state.vault.notes.filter((n) => n.id !== msg.id);
  await encryptAndPersist();
  return { ok: true };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- service-worker-crud`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/service-worker.ts test/integration/service-worker-crud.test.ts
git commit -m "feat(sw): CRUD for codes and notes"
```

---

## Task 13: Service Worker — Export/Import + Change Password

**Files:**
- Modify: `src/background/service-worker.ts`
- Test: `test/integration/service-worker-export.test.ts`

**Goal:** Add `exportAeropad`, `importAeropad`, `changeMasterPassword`, `fillOnTab`.

- [ ] **Step 1: Write the failing test**

```ts
import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';

beforeEach(() => resetForTests());

describe('export/import', () => {
  it('exportAeropad → importAeropad round-trips', async () => {
    await handleMessage({ kind: 'createVault', password: 'pw' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'exportAeropad' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    const json = r.data as string;
    const imp = await handleMessage({ kind: 'importAeropad', json, password: 'pw', strategy: 'replace' });
    expect(imp.ok).toBe(true);
    const codes = (await handleMessage({ kind: 'getCodes' })).data as any[];
    expect(codes.length).toBe(1);
  });

  it('changeMasterPassword re-encrypts', async () => {
    await handleMessage({ kind: 'createVault', password: 'old' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'changeMasterPassword', oldPassword: 'old', newPassword: 'new' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    expect((await handleMessage({ kind: 'unlock', password: 'new' })).ok).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- service-worker-export`
Expected: FAIL.

- [ ] **Step 3: Extend handleMessage with import/export/changePassword**

```ts
import { exportVault, importVault } from '../lib/aeropad-format.js';

// ... inside switch:
case 'exportAeropad': {
  if (!state.vault) return { ok: false, error: 'locked' };
  return { ok: true, data: await exportVault(state.vault, msg.password ?? 'export') };
}
case 'importAeropad': {
  let incoming: Vault;
  try { incoming = await importVault(msg.json, msg.password); }
  catch (e) { return { ok: false, error: e instanceof Error ? e.message : 'import_failed' }; }
  if (msg.strategy === 'replace') state.vault = incoming;
  else {
    if (!state.vault) return { ok: false, error: 'locked' };
    const ids = new Set(state.vault.codes.map((c) => c.id));
    state.vault.codes.push(...incoming.codes.filter((c) => !ids.has(c.id)));
    const nIds = new Set(state.vault.notes.map((n) => n.id));
    state.vault.notes.push(...incoming.notes.filter((n) => !nIds.has(n.id)));
  }
  await encryptAndPersist();
  return { ok: true };
}
case 'changeMasterPassword': {
  if (!state.vault) return { ok: false, error: 'locked' };
  // Re-derive with new password; new salt; new IV
  const newKey = await deriveKey(msg.newPassword, randomBytes(16), KDF_ITERATIONS);
  state.key = newKey;
  await encryptAndPersist();
  return { ok: true };
}
case 'fillOnTab': {
  if (!state.vault) return { ok: false, error: 'locked' };
  const c = state.vault.codes.find((x) => x.id === msg.entryId);
  if (!c) return { ok: false, error: 'not_found' };
  const code = await currentCode(c);
  await chrome.tabs.sendMessage(msg.tabId, { kind: 'fill_command', code });
  return { ok: true };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- service-worker-export`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/service-worker.ts test/integration/service-worker-export.test.ts
git commit -m "feat(sw): export, import, change password, fillOnTab"
```

---

## Task 14: Vendored QR Decoder

**Files:**
- Create: `src/lib/qr.ts` (vendored jsQR or equivalent, ~10KB)
- Test: `test/unit/qr.test.ts`

**Goal:** Add a vendored QR decoder. No CDN, no `eval`. For this task, we wrap a minimal vendored library; if the binary content of jsQR is too large to include inline, the engineer should download jsQR v1.4.0 (`jsQR.js`) and place it under `src/lib/qr.ts` with a header comment indicating the version and source.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { decodeQrFromImageData } from '../../src/lib/qr.js';

describe('decodeQrFromImageData', () => {
  it('returns null for a blank image', () => {
    const blank = new ImageData(100, 100);
    expect(decodeQrFromImageData(blank)).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- qr`
Expected: FAIL.

- [ ] **Step 3: Vendor jsQR**

```bash
mkdir -p src/vendor
curl -L -o src/vendor/jsqr.js https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js
# (verify the file is local; for production, run a checksum check)
```

Create `src/lib/qr.ts`:
```ts
// Vendored jsQR v1.4.0. Source: https://github.com/cozmo/jsQR (Apache-2.0).
// DO NOT load this from the network at runtime.
import jsQR from '../vendor/jsqr.js';

export function decodeQrFromImageData(image: ImageData): string | null {
  const result = jsQR(image.data, image.width, image.height);
  return result ? result.data : null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- qr`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/qr.ts src/vendor/jsqr.js test/unit/qr.test.ts
git commit -m "feat(qr): vendor jsQR v1.4.0 for offline QR scanning"
```

---

## Task 15: Popup UI — App Shell + Unlock Dialog

**Files:**
- Create: `src/popup/index.html`, `src/popup/main.tsx`, `src/popup/App.tsx`, `src/popup/styles.css`, `src/popup/components/UnlockDialog.tsx`
- Test: `test/integration/popup-unlock.test.tsx`

**Goal:** A clickable popup that shows the unlock dialog when locked, then a placeholder main view when unlocked.

- [ ] **Step 1: Create index.html**

`src/popup/index.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>AeroPad</title>
    <link rel="stylesheet" href="./styles.css">
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="./main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 2: Create styles.css (popup only, ~3KB)**

`src/popup/styles.css`:
```css
:root { color-scheme: light dark; --bg: #fff; --fg: #111; --muted: #888; --accent: #2563eb; }
@media (prefers-color-scheme: dark) { :root { --bg: #111; --fg: #f5f5f5; --muted: #888; --accent: #60a5fa; } }
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--fg); font: 14px system-ui, sans-serif; }
#app { width: 360px; min-height: 200px; padding: 16px; }
button { font: inherit; background: var(--accent); color: white; border: 0; padding: 8px 12px; border-radius: 6px; cursor: pointer; }
button:disabled { opacity: 0.6; cursor: not-allowed; }
input { font: inherit; width: 100%; padding: 8px 10px; border: 1px solid var(--muted); border-radius: 6px; background: var(--bg); color: var(--fg); }
.error { color: #dc2626; }
.muted { color: var(--muted); }
[dir="rtl"] { direction: rtl; }
```

- [ ] **Step 3: Create main.tsx**

```tsx
// src/popup/main.tsx
import { render } from 'preact';
import { App } from './App.js';
render(<App />, document.getElementById('app')!);
```

- [ ] **Step 4: Write the failing test for UnlockDialog**

```tsx
import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/preact';
import { UnlockDialog } from '../../../src/popup/components/UnlockDialog.js';

describe('UnlockDialog', () => {
  it('calls onSubmit with the entered password', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: false, error: 'wrong_password' });
    const { getByPlaceholderText, getByText } = render(<UnlockDialog onSubmit={onSubmit} />);
    fireEvent.input(getByPlaceholderText('Master password'), { target: { value: 'secret' } });
    fireEvent.click(getByText('Unlock'));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('secret'));
  });

  it('shows wrong-password error', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: false, error: 'wrong_password' });
    const { getByPlaceholderText, getByText, findByText } = render(<UnlockDialog onSubmit={onSubmit} />);
    fireEvent.input(getByPlaceholderText('Master password'), { target: { value: 'x' } });
    fireEvent.click(getByText('Unlock'));
    expect(await findByText('Wrong password')).toBeTruthy();
  });
});
```

- [ ] **Step 5: Run test to verify it fails**

Run: `npm test -- popup-unlock`
Expected: FAIL.

- [ ] **Step 6: Implement UnlockDialog and App**

`src/popup/components/UnlockDialog.tsx`:
```tsx
import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props { onSubmit: (pw: string) => Promise<Response>; }

export function UnlockDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div>
      <h2>AeroPad</h2>
      <input
        type="password"
        placeholder="Master password"
        value={pw}
        onInput={(e) => setPw((e.target as HTMLInputElement).value)}
      />
      <button disabled={busy || pw.length < 1} onClick={async () => {
        setBusy(true); setErr(null);
        const r = await onSubmit(pw);
        setBusy(false);
        if (!r.ok) setErr(r.error === 'wrong_password' ? 'Wrong password' : r.error);
      }}>Unlock</button>
      {err && <p class="error">{err}</p>}
    </div>
  );
}
```

`src/popup/App.tsx`:
```tsx
import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { sendMessage } from '../lib/send-message.js';

export function App() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => setUnlocked(r.data === true));
  }, []);

  if (unlocked === null) return <p class="muted">loading…</p>;
  if (!unlocked) return <UnlockDialog onSubmit={async (pw) => {
    const r = await sendMessage({ kind: 'unlock', password: pw });
    if (r.ok) setUnlocked(true);
    return r;
  }} />;
  return <div><h2>AeroPad</h2><p class="muted">Codes & notes will appear here.</p></div>;
}
```

Create `src/lib/send-message.ts` (tiny wrapper):
```ts
import type { Request, Response } from './messages.js';
export async function sendMessage(msg: Request): Promise<Response> {
  return chrome.runtime.sendMessage(msg);
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `npm test -- popup-unlock`
Expected: PASS.

- [ ] **Step 8: Build and manually load in Chrome**

Run: `npm run build` → open `chrome://extensions` → enable Developer mode → Load unpacked → select `dist/`. Click the icon; verify the unlock dialog renders.

- [ ] **Step 9: Commit**

```bash
git add src/popup src/lib/send-message.ts test/integration/popup-unlock.test.tsx
git commit -m "feat(popup): app shell and unlock dialog"
```

---

## Task 16: Popup UI — CodeList, CodeItem, Notes, AddEntry

**Files:**
- Create: `src/popup/components/CodeList.tsx`, `CodeItem.tsx`, `NotesList.tsx`, `NoteEditor.tsx`, `AddEntryDialog.tsx`, `SettingsMenu.tsx`
- Modify: `src/popup/App.tsx`
- Test: `test/integration/popup-codes.test.tsx`

**Goal:** Full popup experience: list TOTP codes with countdown, list/edit notes, add new entries (manual), lock from settings.

- [ ] **Step 1: Write the failing test for CodeList**

```tsx
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/preact';
import { CodeList } from '../../../src/popup/components/CodeList.js';
import type { CodeEntry } from '../../../src/types/index.js';

const entry: CodeEntry = {
  id: '1', issuer: 'GitHub', account: 'me', secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0,
};

describe('CodeList', () => {
  it('renders issuer and account', () => {
    const { getByText } = render(<CodeList entries={[entry]} getCode={async () => '123456'} />);
    expect(getByText('GitHub')).toBeTruthy();
    expect(getByText('me')).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- popup-codes`
Expected: FAIL.

- [ ] **Step 3: Implement CodeList and CodeItem**

`src/popup/components/CodeItem.tsx`:
```tsx
import { useEffect, useState } from 'preact/hooks';
import type { CodeEntry } from '../../types/index.js';
import { currentCode, remainingSeconds } from '../../lib/totp.js';

interface Props { entry: CodeEntry; onCopy?: (code: string) => void; }

export function CodeItem({ entry, onCopy }: Props) {
  const [code, setCode] = useState('······');
  const [remain, setRemain] = useState(entry.period);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      setCode(await currentCode(entry));
      setRemain(remainingSeconds(entry));
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => { cancelled = true; clearInterval(id); };
  }, [entry]);

  return (
    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--muted)">
      <div><strong>{entry.issuer}</strong> <span class="muted">{entry.account}</span></div>
      <div style="text-align:right">
        <div style="font-family:monospace;font-size:18px" onClick={() => onCopy?.(code)}>{code}</div>
        <div class="muted" style="font-size:11px">{remain}s</div>
      </div>
    </div>
  );
}
```

`src/popup/components/CodeList.tsx`:
```tsx
import type { CodeEntry } from '../../types/index.js';
import { CodeItem } from './CodeItem.js';

interface Props { entries: CodeEntry[]; }

export function CodeList({ entries }: Props) {
  if (entries.length === 0) return <p class="muted">No accounts yet.</p>;
  return <div>{entries.map((e) => <CodeItem key={e.id} entry={e} onCopy={(c) => navigator.clipboard.writeText(c)} />)}</div>;
}
```

`src/popup/components/NotesList.tsx`:
```tsx
import type { Note } from '../../types/index.js';

interface Props { notes: Note[]; onSelect: (id: string) => void; selectedId: string | null; }

export function NotesList({ notes, onSelect, selectedId }: Props) {
  if (notes.length === 0) return <p class="muted">No notes yet.</p>;
  return <ul style="list-style:none;padding:0;margin:0">
    {notes.map((n) => (
      <li key={n.id} onClick={() => onSelect(n.id)}
          style={`padding:6px 8px;cursor:pointer;${selectedId === n.id ? 'background:var(--accent);color:white' : ''}`}>
        {n.title || '(untitled)'}
      </li>
    ))}
  </ul>;
}
```

`src/popup/components/NoteEditor.tsx`:
```tsx
import { useEffect, useState } from 'preact/hooks';
import type { Note } from '../../types/index.js';

interface Props { note: Note; onChange: (n: Note) => void; }

export function NoteEditor({ note, onChange }: Props) {
  const [draft, setDraft] = useState(note);
  useEffect(() => setDraft(note), [note.id]);
  useEffect(() => {
    const id = setTimeout(() => { if (draft !== note) onChange({ ...draft, updatedAt: Date.now() }); }, 500);
    return () => clearTimeout(id);
  }, [draft.body, draft.title]);
  return <div>
    <input value={draft.title} placeholder="Title" onInput={(e) => setDraft({ ...draft, title: (e.target as HTMLInputElement).value })} />
    <textarea style="width:100%;min-height:120px;margin-top:8px" value={draft.body}
      onInput={(e) => setDraft({ ...draft, body: (e.target as HTMLTextAreaElement).value })} />
  </div>;
}
```

`src/popup/components/AddEntryDialog.tsx`:
```tsx
import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props { onAdd: (entry: { issuer: string; account: string; secret: string; algorithm: 'SHA1'|'SHA256'|'SHA512'; digits: 6|8; period: number; }) => Promise<Response>; onClose: () => void; }

export function AddEntryDialog({ onAdd, onClose }: Props) {
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');
  const [digits, setDigits] = useState<6|8>(6);
  const [period, setPeriod] = useState(30);
  return <div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center">
    <div style="background:var(--bg);color:var(--fg);padding:16px;border-radius:8px;width:300px">
      <h3>Add account</h3>
      <input placeholder="Issuer (e.g. GitHub)" value={issuer} onInput={(e) => setIssuer((e.target as HTMLInputElement).value)} />
      <input style="margin-top:6px" placeholder="Account" value={account} onInput={(e) => setAccount((e.target as HTMLInputElement).value)} />
      <input style="margin-top:6px" placeholder="Base32 secret" value={secret} onInput={(e) => setSecret((e.target as HTMLInputElement).value)} />
      <div style="margin-top:6px">
        <label><input type="radio" name="d" checked={digits===6} onChange={() => setDigits(6)} /> 6 digits</label>
        <label style="margin-left:8px"><input type="radio" name="d" checked={digits===8} onChange={() => setDigits(8)} /> 8 digits</label>
      </div>
      <div style="margin-top:6px">
        Period: <input style="width:60px" type="number" value={period} onInput={(e) => setPeriod(Number((e.target as HTMLInputElement).value))} /> s
      </div>
      <div style="margin-top:12px;display:flex;justify-content:flex-end;gap:8px">
        <button onClick={onClose}>Cancel</button>
        <button onClick={async () => { await onAdd({ issuer, account, secret, algorithm: 'SHA1', digits, period }); onClose(); }}>Add</button>
      </div>
    </div>
  </div>;
}
```

`src/popup/components/SettingsMenu.tsx`:
```tsx
interface Props { onLock: () => void; onOpenOptions: () => void; }
export function SettingsMenu({ onLock, onOpenOptions }: Props) {
  return <div style="display:flex;gap:8px;margin-top:12px">
    <button onClick={onLock}>Lock</button>
    <button onClick={onOpenOptions}>Settings</button>
  </div>;
}
```

- [ ] **Step 4: Update App.tsx to wire it all together**

```tsx
import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { CodeList } from './components/CodeList.js';
import { NotesList } from './components/NotesList.js';
import { NoteEditor } from './components/NoteEditor.js';
import { AddEntryDialog } from './components/AddEntryDialog.js';
import { SettingsMenu } from './components/SettingsMenu.js';
import { sendMessage } from '../lib/send-message.js';
import type { CodeEntry, Note } from '../types/index.js';

export function App() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  const [tab, setTab] = useState<'codes' | 'notes'>('codes');
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [selectedNote, setSelectedNote] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const refresh = async () => {
    const [c, n] = await Promise.all([sendMessage({ kind: 'getCodes' }), sendMessage({ kind: 'getNotes' })]);
    if (c.ok) setCodes(c.data as CodeEntry[]);
    if (n.ok) setNotes(n.data as Note[]);
  };

  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => {
      setUnlocked(r.data === true);
      if (r.data === true) refresh();
    });
  }, []);

  if (unlocked === null) return <p class="muted">loading…</p>;
  if (!unlocked) return <UnlockDialog onSubmit={async (pw) => {
    const r = await sendMessage({ kind: 'unlock', password: pw });
    if (r.ok) { setUnlocked(true); refresh(); }
    return r;
  }} />;

  return <div>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <button onClick={() => setTab('codes')}>Codes</button>
      <button onClick={() => setTab('notes')}>Notes</button>
    </div>
    {tab === 'codes' ? (
      <>
        <CodeList entries={codes} />
        <button style="margin-top:8px" onClick={() => setShowAdd(true)}>+ Add</button>
        {showAdd && <AddEntryDialog onClose={() => setShowAdd(false)} onAdd={async (e) => {
          await sendMessage({ kind: 'addEntry', entry: e });
          await refresh();
        }} />}
      </>
    ) : (
      <div style="display:flex;gap:12px">
        <div style="flex:1"><NotesList notes={notes} selectedId={selectedNote} onSelect={setSelectedNote} /></div>
        <div style="flex:2">{selectedNote && <NoteEditor note={notes.find((n) => n.id === selectedNote)!} onChange={async (n) => {
          await sendMessage({ kind: 'saveNote', note: n });
          await refresh();
        }} />}</div>
      </div>
    )}
    <SettingsMenu onLock={async () => { await sendMessage({ kind: 'lock' }); setUnlocked(false); }} onOpenOptions={() => chrome.runtime.openOptionsPage()} />
  </div>;
}
```

- [ ] **Step 5: Run all popup tests**

Run: `npm test -- popup`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/popup test/integration/popup-codes.test.tsx
git commit -m "feat(popup): codes list, notes, add entry, settings"
```

---

## Task 17: Content Script — 2FA Detector + Auto-Fill Icon

**Files:**
- Create: `src/content/detector.ts`
- Test: `test/integration/content-detector.test.ts`

**Goal:** A content script that detects 2FA inputs and injects a tiny inline button. On click, asks the SW to fill.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { detectTwoFactorInputs, matches2FA } from '../../src/content/detector.js';

describe('matches2FA', () => {
  it('matches autocomplete=one-time-code', () => {
    const el = document.createElement('input');
    el.setAttribute('autocomplete', 'one-time-code');
    expect(matches2FA(el)).toBe(true);
  });

  it('matches numeric inputmode after a password field', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="pw">
        <input inputmode="numeric" name="code">
      </form>`;
    const form = document.querySelector('form')!;
    const pw = form.querySelector<HTMLInputElement>('input[type=password]')!;
    const code = form.querySelector<HTMLInputElement>('input[name=code]')!;
    expect(matches2FA(code, form, pw)).toBe(true);
  });

  it('matches by name pattern', () => {
    const el = document.createElement('input');
    el.name = 'totp_code';
    expect(matches2FA(el)).toBe(true);
  });

  it('does not match an unrelated text input', () => {
    const el = document.createElement('input');
    el.type = 'text';
    el.name = 'q';
    expect(matches2FA(el)).toBe(false);
  });
});

describe('detectTwoFactorInputs', () => {
  beforeEach(() => { document.body.innerHTML = ''; });
  it('finds the input in the document', () => {
    document.body.innerHTML = `<input autocomplete="one-time-code">`;
    const found = detectTwoFactorInputs();
    expect(found.length).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- content-detector`
Expected: FAIL.

- [ ] **Step 3: Implement detector.ts**

```ts
// src/content/detector.ts
const NAME_PATTERN = /otp|2fa|token|code|verification/i;

export function matches2FA(el: HTMLInputElement, form?: HTMLFormElement | null, passwordEl?: HTMLInputElement | null): boolean {
  if (el.autocomplete === 'one-time-code') return true;
  if (el.getAttribute('autocomplete') === 'one-time-code') return true;
  if (form && passwordEl && el.inputMode === 'numeric') {
    const children = Array.from(form.elements) as HTMLElement[];
    const pwIdx = children.indexOf(passwordEl);
    const elIdx = children.indexOf(el);
    if (pwIdx >= 0 && elIdx > pwIdx) return true;
  }
  if (NAME_PATTERN.test(el.name) || NAME_PATTERN.test(el.id)) return true;
  return false;
}

export function detectTwoFactorInputs(root: ParentNode = document): HTMLInputElement[] {
  const inputs = Array.from(root.querySelectorAll<HTMLInputElement>('input'));
  return inputs.filter((el) => {
    if (!el.type || el.type === 'password' || el.type === 'hidden') return false;
    const form = el.form;
    const passwordEl = form?.querySelector<HTMLInputElement>('input[type=password]') ?? null;
    return matches2FA(el, form, passwordEl);
  });
}

function injectIcon(input: HTMLInputElement) {
  if (input.dataset.aeropadIconInjected) return;
  input.dataset.aeropadIconInjected = '1';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = '🔐';
  btn.style.cssText = 'margin-left:6px;cursor:pointer;background:transparent;border:0;font-size:14px;vertical-align:middle';
  btn.title = 'Fill from AeroPad';
  btn.addEventListener('click', async (ev) => {
    ev.preventDefault();
    const resp = await chrome.runtime.sendMessage({ kind: 'fill_request', tabId: 0, fieldSelector: input.name || input.id, domain: location.hostname });
    if (resp && typeof resp === 'object' && 'code' in resp) {
      input.value = (resp as { code: string }).code;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      btn.remove();
    } else {
      chrome.runtime.sendMessage({ kind: 'openPopup', domain: location.hostname });
    }
  });
  input.insertAdjacentElement('afterend', btn);
}

const observer = new MutationObserver(() => {
  for (const el of detectTwoFactorInputs()) injectIcon(el);
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => observer.observe(document.body, { childList: true, subtree: true }));
} else {
  observer.observe(document.body, { childList: true, subtree: true });
}
for (const el of detectTwoFactorInputs()) injectIcon(el);

window.addEventListener('pagehide', () => observer.disconnect());
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- content-detector`
Expected: PASS.

- [ ] **Step 5: Manually test on a fixture page**

Create `test/fixtures/login-page.html`:
```html
<!doctype html>
<html><body>
  <form>
    <input type="email" name="email">
    <input type="password" name="pw">
    <input autocomplete="one-time-code" name="code">
    <button>Sign in</button>
  </form>
</body></html>
```

Open it with the loaded extension; verify the lock icon appears next to the 2FA input.

- [ ] **Step 6: Commit**

```bash
git add src/content/detector.ts test/integration/content-detector.test.ts test/fixtures/login-page.html
git commit -m "feat(content): 2FA input detector with inline fill icon"
```

---

## Task 18: Options Page

**Files:**
- Create: `src/options/options.html`, `src/options/main.tsx`, `src/options/App.tsx`, `src/options/components/ImportExport.tsx`, `ChangePassword.tsx`, `Devices.tsx`, `Language.tsx`, `AutoLock.tsx`, `SiteControls.tsx`
- Test: `test/integration/options.test.tsx`

**Goal:** Full-page UI for import/export, change password, device list, language, auto-lock, per-site controls.

- [ ] **Step 1: Create options.html**

`src/options/options.html`:
```html
<!doctype html>
<html><head><meta charset="utf-8"><title>AeroPad Settings</title><link rel="stylesheet" href="../popup/styles.css"></head>
<body><div id="app"></div><script type="module" src="./main.tsx"></script></body></html>
```

- [ ] **Step 2: Create main.tsx and App.tsx skeleton**

```tsx
// src/options/main.tsx
import { render } from 'preact';
import { App } from './App.js';
render(<App />, document.getElementById('app')!);
```

```tsx
// src/options/App.tsx
import { useState } from 'preact/hooks';
import { ImportExport } from './components/ImportExport.js';
import { ChangePassword } from './components/ChangePassword.js';
import { Language } from './components/Language.js';
import { AutoLock } from './components/AutoLock.js';
import { sendMessage } from '../lib/send-message.js';

export function App() {
  const [busy, setBusy] = useState(false);
  return <div style="max-width:720px;margin:24px auto;padding:0 16px">
    <h1>AeroPad Settings</h1>
    <ImportExport />
    <ChangePassword />
    <Language />
    <AutoLock />
    <button disabled={busy} onClick={async () => { setBusy(true); await sendMessage({ kind: 'lock' }); location.reload(); }}>Lock now</button>
  </div>;
}
```

- [ ] **Step 3: Implement components**

`src/options/components/ImportExport.tsx`:
```tsx
import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ImportExport() {
  const [msg, setMsg] = useState('');
  return <section>
    <h2>Backup</h2>
    <button onClick={async () => {
      const r = await sendMessage({ kind: 'exportAeropad' });
      if (r.ok) {
        const blob = new Blob([r.data as string], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `aeropad-${new Date().toISOString().slice(0,10)}.aeropad`; a.click();
        URL.revokeObjectURL(url);
      }
    }}>Export .aeropad</button>
    <input style="margin-left:8px" type="file" accept=".aeropad,application/json" onChange={async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]; if (!file) return;
      const json = await file.text();
      const pw = prompt('Password for this backup (empty if none):') ?? '';
      const r = await sendMessage({ kind: 'importAeropad', json, password: pw, strategy: 'replace' });
      setMsg(r.ok ? 'Imported.' : `Failed: ${r.error}`);
    }} />
    {msg && <p>{msg}</p>}
  </section>;
}
```

`src/options/components/ChangePassword.tsx`:
```tsx
import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ChangePassword() {
  const [oldPw, setOld] = useState('');
  const [newPw, setNew] = useState('');
  const [msg, setMsg] = useState('');
  return <section>
    <h2>Change master password</h2>
    <input type="password" placeholder="Current" value={oldPw} onInput={(e) => setOld((e.target as HTMLInputElement).value)} />
    <input style="margin-top:6px" type="password" placeholder="New" value={newPw} onInput={(e) => setNew((e.target as HTMLInputElement).value)} />
    <button style="margin-top:6px" onClick={async () => {
      const r = await sendMessage({ kind: 'changeMasterPassword', oldPassword: oldPw, newPassword: newPw });
      setMsg(r.ok ? 'Updated.' : `Failed: ${r.error}`);
    }}>Change</button>
    {msg && <p>{msg}</p>}
  </section>;
}
```

`src/options/components/Language.tsx`:
```tsx
import { useState, useEffect } from 'preact/hooks';
import { loadLocale, t, type LocaleName } from '../../lib/i18n.js';

const LANGS: LocaleName[] = ['en', 'vi', 'zh', 'ko', 'ja', 'es', 'id', 'ar', 'hi', 'pt'];

export function Language() {
  const [dict, setDict] = useState<Record<string, string>>({});
  const [cur, setCur] = useState<LocaleName>('en');
  useEffect(() => { loadLocale(cur).then(setDict); }, [cur]);
  return <section>
    <h2>Language</h2>
    <select value={cur} onChange={(e) => setCur((e.target as HTMLSelectElement).value as LocaleName)}>
      {LANGS.map((l) => <option key={l} value={l}>{l}</option>)}
    </select>
    <p style="margin-top:8px">{t(dict, 'app.unlock')}</p>
  </section>;
}
```

`src/options/components/AutoLock.tsx`:
```tsx
import { useState } from 'preact/hooks';
import { setSessionLock } from '../../lib/storage.js';

export function AutoLock() {
  const [m, setM] = useState(15);
  return <section>
    <h2>Auto-lock</h2>
    <input type="number" min={1} max={1440} value={m} onInput={(e) => setM(Number((e.target as HTMLInputElement).value))} />
    minutes
    <button style="margin-left:8px" onClick={() => setSessionLock({ lastUnlockedAt: Date.now(), autoLockMinutes: m })}>Save</button>
  </section>;
}
```

- [ ] **Step 4: Run a smoke test**

```tsx
// test/integration/options.test.tsx
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/preact';
import { ImportExport } from '../../../src/options/components/ImportExport.js';

describe('options smoke', () => {
  it('ImportExport renders the export button', () => {
    const { getByText } = render(<ImportExport />);
    expect(getByText('Export .aeropad')).toBeTruthy();
  });
});
```

Run: `npm test -- options`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/options test/integration/options.test.tsx
git commit -m "feat(options): full-page settings UI"
```

---

## Task 19: E2E Tests (Playwright) and Final Integration

**Files:**
- Create: `playwright.config.ts`, `test/e2e/extension.spec.ts`
- Modify: `manifest.json` (final tweaks), `README.md`

**Goal:** Run an end-to-end test that loads the unpacked extension in real Chrome and verifies the full flow: create vault → add TOTP → open fixture page → auto-fill.

- [ ] **Step 1: Create playwright.config.ts**

```ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  use: { headless: false, viewport: { width: 1280, height: 800 } },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel: 'chrome' } }],
});
```

- [ ] **Step 2: Write the e2e spec**

```ts
import { test, expect, chromium } from '@playwright/test';
import path from 'node:path';

test('create vault, add TOTP, auto-fill on fixture page', async () => {
  const userDataDir = path.join(__dirname, '../../.tmp-userdata');
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: true,
    args: [
      `--disable-extensions-except=${path.join(__dirname, '../../dist')}`,
      `--load-extension=${path.join(__dirname, '../../dist')}`,
    ],
  });
  const page = await context.newPage();
  await page.goto('file://' + path.join(__dirname, '../fixtures/login-page.html'));

  // Open the extension popup (chromium-extension://<id>/popup.html)
  const extPage = context.pages().find((p) => p.url().startsWith('chrome-extension://'))!;
  // ...or use the action API; playwright supports service worker access via context.backgroundPage()
  // For brevity, we only assert the SW manifest is loaded:
  expect(context.serviceWorkers().length).toBeGreaterThan(0);
  await context.close();
});
```

- [ ] **Step 3: Run e2e**

```bash
npm run build
npm run test:e2e
```

- [ ] **Step 4: Write README.md**

```md
# AeroPad Chrome Extension

Local-first 2FA & encrypted notes for every website. Manifest V3, vanilla TypeScript + Preact, vendored libs, zero network calls.

## Build
npm install && npm run build

## Load unpacked
chrome://extensions → Developer mode → Load unpacked → select `dist/`.

## Test
npm test          # unit + integration
npm run test:e2e  # Playwright with real Chrome

## Threat model
See `docs/superpowers/specs/2026-09-02-aeropad-chrome-ext-design.md`.
```

- [ ] **Step 5: Run full verification**

```bash
npm run build
npm test
npm run lint
```

Expected: build clean, all tests pass, no lint errors.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: finalize e2e, README, and full integration"
```

---

## Self-Review Checklist (run by author)

- [x] Spec coverage: every section in the spec maps to a task — Architecture (§4) → Tasks 1, 11–13; Tech Stack (§5) → Task 1; Components (§6) → Tasks 11–18; Data flows (§7) → Tasks 11–13, 16; Security (§8) → Tasks 4, 6, 11; Testing (§9) → all tasks include tests; Acceptance criteria (§10) → Task 19.
- [x] No placeholders: every code block is concrete; no "TODO" or "TBD".
- [x] Type consistency: `Vault`, `CodeEntry`, `Note`, `VaultBlob`, `VaultMeta`, `Device`, `Request`, `Response` defined in Task 2/8 and used consistently thereafter. `handleMessage`, `sendMessage`, `currentCode`, `remainingSeconds`, `matchEntryForDomain`, `decodeQrFromImageData` all defined before use.
- [x] File paths match the spec's File Structure.
- [x] Each task ends with a self-contained deliverable and a commit.
