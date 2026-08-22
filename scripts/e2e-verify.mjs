/**
 * E2E verification of the AeroPad fixes — runs the REAL index.html + app.js in jsdom
 * with a controllable clock, recording clipboard, and RFC-verified reference codes.
 *
 * Requires: npm i --no-save jsdom
 * Run:      node scripts/e2e-verify.mjs
 *
 * NOTE: jsdom fires the real DOMContentLoaded asynchronously after construction.
 * We eval app.js synchronously (listener attaches first), then AWAIT that single
 * real event — never dispatch a synthetic one, which would double-attach handlers.
 */
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { JSDOM } from 'jsdom';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rootPath = relativePath => resolve(root, relativePath);
const rootModule = relativePath => pathToFileURL(rootPath(relativePath)).href;
const require = createRequire(import.meta.url);
const qrcodeLib = require('qrcode-generator');
const jsqrSource = readFileSync(rootPath('node_modules/jsqr/dist/jsQR.js'), 'utf8');

const html = readFileSync(rootPath('index.html'), 'utf8');
const appJs = readFileSync(rootPath('app.js'), 'utf8');
const { generateTOTP: refTOTP } = await import(rootModule('src/crypto/totp.js'));
const { decryptVault, encryptVault } = await import(rootModule('src/crypto/vault-crypto.js'));
const { IndexedDBVaultAdapter } = await import(rootModule('src/storage/indexeddb-adapter.js'));
const { readLegacyVault } = await import(rootModule('src/storage/legacy-migration.js'));

const SECRET = 'JBSWY3DPEHPK3PXP';
let fakeNowMs;
let clipboardCalls = [];
let confirmResponses = [];
let backupDownloads = [];

// Cross-realm safe WebCrypto shim: jsdom ArrayBuffers fail Node's instanceof checks,
// so copy bytes into a Node Buffer before handing them to webcrypto.
function makeSubtleShim(window) {
  const toNodeBuffer = (data) => {
    const view = data instanceof window.Uint8Array ? data : new window.Uint8Array(data);
    const out = Buffer.alloc(view.length);
    for (let i = 0; i < view.length; i++) out[i] = view[i];
    return out;
  };
  return {
    importKey: (fmt, data, alg, ext, usages) => webcrypto.subtle.importKey(fmt, toNodeBuffer(data), alg, ext, usages),
    sign: (alg, key, data) => webcrypto.subtle.sign(alg, key, toNodeBuffer(data)),
    deriveKey: (spec, base, derived, ext, usages) => webcrypto.subtle.deriveKey(
      { name: spec.name, salt: toNodeBuffer(spec.salt), iterations: spec.iterations, hash: spec.hash },
      base, derived, ext, usages
    ),
    encrypt: (alg, key, data) => webcrypto.subtle.encrypt({
      name: alg.name,
      iv: toNodeBuffer(alg.iv),
      ...(alg.additionalData ? { additionalData: toNodeBuffer(alg.additionalData) } : {}),
      ...(alg.tagLength ? { tagLength: alg.tagLength } : {})
    }, key, toNodeBuffer(data)),
    decrypt: (alg, key, data) => webcrypto.subtle.decrypt({
      name: alg.name,
      iv: toNodeBuffer(alg.iv),
      ...(alg.additionalData ? { additionalData: toNodeBuffer(alg.additionalData) } : {}),
      ...(alg.tagLength ? { tagLength: alg.tagLength } : {})
    }, key, toNodeBuffer(data)),
    digest: (alg, data) => webcrypto.subtle.digest(alg, toNodeBuffer(data)),
  };
}

function setupWindow(window) {
  const RealDate = window.Date;
  const captured = fakeNowMs;
  class FakeDate extends RealDate {
    static now() { return captured; }
  }
  // bind to the module-level live value so later fakeNowMs changes are honored
  Object.defineProperty(FakeDate, 'now', { value: () => fakeNowMs });
  window.Date = FakeDate;

  Object.defineProperty(window.crypto, 'subtle', { value: makeSubtleShim(window), configurable: true });
  Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
  Object.defineProperty(window.navigator, 'clipboard', {
    value: { writeText: async (text) => { clipboardCalls.push(text); } },
    configurable: true,
  });
  Object.defineProperty(window.URL, 'createObjectURL', {
    value: blob => { backupDownloads.push(blob); return `blob:e2e-${backupDownloads.length}`; },
    configurable: true,
  });
  Object.defineProperty(window.URL, 'revokeObjectURL', { value: () => {}, configurable: true });
  window.confirm = () => confirmResponses.shift() ?? false;
  window.Element.prototype.scrollIntoView = () => {};
  window.HTMLAnchorElement.prototype.click = function () {};
  // jsdom lacks TextEncoder/TextDecoder — the app uses them for AES payloads
  if (!window.TextEncoder) window.TextEncoder = TextEncoder;
  if (!window.TextDecoder) window.TextDecoder = TextDecoder;
}

function makeIndexedDBHarness() {
  const records = new Map();
  let hasStore = false;
  const api = { failNext: false, holdNext: false, heldPut: null, records,
    releaseHeld() {
      const release = api.heldPut;
      api.heldPut = null;
      release?.();
    },
    open() {
    const request = {};
    queueMicrotask(() => {
      const database = {
        objectStoreNames: { contains: () => hasStore },
        createObjectStore: () => { hasStore = true; },
        transaction: () => {
          const tx = { oncomplete: null, onerror: null, onabort: null, record: null };
          tx.objectStore = () => ({
            get: key => { const result = {}; queueMicrotask(() => { result.result = records.get(key); result.onsuccess?.({ target: result }); tx.oncomplete?.(); }); return result; },
            put: record => {
              tx.record = record;
              const result = {};
              const complete = () => {
                if (api.failNext) {
                  api.failNext = false;
                  result.error = new Error('transaction failed');
                  result.onerror?.({ target: result });
                  tx.onerror?.({ target: tx });
                  tx.onabort?.({ target: tx });
                  return;
                }
                records.set('current', tx.record);
                result.onsuccess?.({ target: result });
                tx.oncomplete?.();
              };
              queueMicrotask(() => {
                if (api.holdNext) {
                  api.holdNext = false;
                  api.heldPut = complete;
                  return;
                }
                complete();
              });
              return result;
            }
          });
          return tx;
        }
      };
      request.result = database;
      request.onupgradeneeded?.({ target: request });
      request.onsuccess?.({ target: request });
    });
    return request;
  } };
  return api;
}

async function boot({ preSeed, fakes } = {}) {
  fakeNowMs = 1755800000000; // arbitrary epoch, lands mid-window
  clipboardCalls = [];
  confirmResponses = [];
  backupDownloads = [];

  const dom = new JSDOM(html, {
    url: 'http://localhost:8901/index.html',
    runScripts: 'outside-only',
    pretendToBeVisual: true,
  });
  const { window } = dom;
  if (preSeed) preSeed(window);
  setupWindow(window);
  if (fakes) fakes(window); // browser APIs jsdom lacks (Image/canvas for QR)
  window.eval(appJs);

  // Wait for jsdom's ONE real DOMContentLoaded (fires on the next tick)
  await new Promise((resolve) => {
    if (window.document.readyState !== 'loading') return resolve();
    window.document.addEventListener('DOMContentLoaded', resolve, { once: true });
  });
  await new Promise(r => setTimeout(r, 50));
  return { dom, window, document: window.document };
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
async function blobText(blob, window) {
  if (typeof blob.text === 'function') return blob.text();
  return new Promise((resolve, reject) => {
    const reader = new window.FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}
// Poll until fn() is truthy (never guess async durations — PBKDF2+AES timing varies)
const waitFor = async (fn, timeoutMs = 15000, step = 150) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if (fn()) return true; } catch {}
    await sleep(step);
  }
  return false;
};
const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
};
const lastToast = (document) => {
  const spans = document.querySelectorAll('.toast-item span:last-child');
  return spans.length ? spans[spans.length - 1].textContent : '(no toast)';
};

// ============================================================
console.log('=== TEST 1: REL-001 — corrupted legacy storage is preserved for recovery ===');
{
  const { dom, window } = await boot({
    preSeed: (w) => {
      w.localStorage.setItem('aeropad_notes', 'CORRUPTED{{{NOT JSON');
      w.localStorage.setItem('aeropad_totp', '{"broken tru');
    },
  });
  const overlay = window.document.getElementById('lockOverlay');
  check('app exposes the lock/recovery state', !!overlay && !overlay.classList.contains('hidden'), '');
  check('corrupt notes remain untouched for recovery', window.localStorage.getItem('aeropad_notes') === 'CORRUPTED{{{NOT JSON');
  check('corrupt TOTP remains untouched for recovery', window.localStorage.getItem('aeropad_totp') === '{"broken tru');
  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 2+3: SEC-002 — copy after crossing the 30s window returns the CURRENT code ===');
{
  const T0 = Math.floor(fakeNowMs / 1000);
  const { dom, document } = await boot();

  document.getElementById('quickAdd2FABtn').click();
  document.getElementById('modalIssuer').value = 'ChatGPT';
  document.getElementById('modalAccount').value = 'user@test.io';
  document.getElementById('modalSecret').value = SECRET;
  document.getElementById('confirmAdd2FABtn').click();
  await sleep(300);

  const cardCodeEl = document.querySelector('.totp-code-text');
  const window1Ref = await refTOTP(SECRET, { timestamp: T0 });
  check('card shows RFC-correct code for window 1',
    cardCodeEl.textContent === window1Ref.slice(0, 3) + ' ' + window1Ref.slice(3),
    `displayed="${cardCodeEl.textContent}" ref="${window1Ref}"`);

  // Advance the clock past the 30s boundary and let one real timer tick fire
  fakeNowMs += 31 * 1000;
  const T1 = Math.floor(fakeNowMs / 1000);
  await sleep(1600);

  const displayedNow = cardCodeEl.textContent.replace(/\s+/g, '');
  const window2Ref = await refTOTP(SECRET, { timestamp: T1 });
  check('card auto-updated to window 2 code', displayedNow === window2Ref,
    `displayed="${displayedNow}" ref="${window2Ref}"`);

  // Click the card copy button — THE bug scenario: must copy the CURRENT code
  document.querySelector('.btn-copy-code').click();
  await sleep(200);
  const copied = clipboardCalls.at(-1);
  check('copy button copies the CURRENT code (SEC-002 fixed)', copied === window2Ref,
    `copied="${copied}" expected="${window2Ref}"`);

  // Also click the card body itself
  document.querySelector('.totp-card').click();
  await sleep(200);
  const copiedViaCard = clipboardCalls.at(-1);
  check('card click copies the CURRENT code', copiedViaCard === window2Ref,
    `copied="${copiedViaCard}"`);

  check('success toast names the copied code', lastToast(document).includes(window2Ref), lastToast(document));

  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 4: SEC-003 — decoder preserves digits/period/algorithm from otpauth URI ===');
{
  const { dom, document } = await boot();
  document.querySelector('.nav-pill[data-tab="totp"]').click();
  document.querySelector('.totp-subpill[data-subtab="decoder"]').click();

  const uri = `otpauth://totp/MyVault:user@web3.io?secret=${SECRET}&issuer=MyVault&digits=8&period=60&algorithm=SHA256`;
  document.getElementById('rawOtpInput').value = uri;
  document.getElementById('decodeBtn').click();
  await sleep(300);

  const live = document.getElementById('decLiveCode').textContent.replace(/\s+/g, '');
  const ref = await refTOTP(SECRET, {
    timestamp: Math.floor(fakeNowMs / 1000), period: 60, digits: 8, algo: 'SHA-256'
  });
  check('decoder live code honors period=60/digits=8/SHA-256', live === ref,
    `live="${live}" ref="${ref}"`);

  document.getElementById('addDecodedToVaultBtn').click();
  await sleep(300);
  check('vault account carries digits=8, period=60, algo=SHA256',
    document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '').length === 8 &&
      document.querySelector('.totp-card-footer')?.textContent.includes('HMAC-SHA-256') &&
      document.querySelector('.totp-card-footer')?.textContent.includes('8 digits') &&
      document.querySelector('.totp-card-footer')?.textContent.includes('60s'),
    document.querySelector('.totp-card-footer')?.textContent);

  const cardTxt = document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  const cardRef = await refTOTP(SECRET, {
    timestamp: Math.floor(fakeNowMs / 1000), period: 60, digits: 8, algo: 'SHA-256'
  });
  check('vault card generates the SHA-256/60s/8-digit code', cardTxt === cardRef,
    `card="${cardTxt}" ref="${cardRef}"`);

  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 4b: TOTP refresh uses each account period and decoder period ===');
{
  const MASTER_PW = 'per-account timer password';
  const indexedDB = makeIndexedDBHarness();
  const initialPayload = {
    schemaVersion: 2,
    notes: [],
    totpAccounts: [
      { id: 'totp-15', issuer: 'P15', account: 'p15@example.io', secret: SECRET, password: '', digits: 6, period: 15, algo: 'SHA1' },
      { id: 'totp-30', issuer: 'P30', account: 'p30@example.io', secret: SECRET, password: '', digits: 8, period: 30, algo: 'SHA256' },
      { id: 'totp-45', issuer: 'P45', account: 'p45@example.io', secret: SECRET, password: '', digits: 6, period: 45, algo: 'SHA512' },
      { id: 'totp-60', issuer: 'P60', account: 'p60@example.io', secret: SECRET, password: '', digits: 8, period: 60, algo: 'SHA1' }
    ],
    metadata: { createdAt: 1755800000000, updatedAt: 1755800000000 }
  };
  indexedDB.records.set('current', await encryptVault(initialPayload, MASTER_PW, { generation: 1, crypto: webcrypto }));

  const b4 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay = b4.document.getElementById('lockOverlay');
  b4.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b4.document.getElementById('unlockVaultBtn').click();
  check('per-account timer test vault unlocks', await waitFor(() => overlay.classList.contains('hidden')));

  const cardFor = id => b4.document.querySelector(`[data-acc-id="${id}"]`);
  const codeFor = id => cardFor(id)?.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  const periodIds = ['totp-15', 'totp-30', 'totp-45', 'totp-60'];
  check('all supported period cards render', await waitFor(() => periodIds.every(id => cardFor(id))));
  const initialCodes = Object.fromEntries(periodIds.map(id => [id, codeFor(id)]));

  b4.document.querySelector('.totp-subpill[data-subtab="decoder"]').click();
  b4.document.getElementById('rawOtpInput').value = `otpauth://totp/Preview:user@example.io?secret=${SECRET}&issuer=Preview&digits=6&period=45&algorithm=SHA512`;
  b4.document.getElementById('decodeBtn').click();
  const decoderInitial = await waitFor(() => /^\d{6}$/.test(b4.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '')));
  check('decoder period=45 preview renders', decoderInitial);

  b4.document.querySelector('.totp-subpill[data-subtab="vault"]').click();
  const advanceClock = async seconds => {
    fakeNowMs += seconds * 1000;
    await sleep(1300);
  };
  await advanceClock(11);
  await advanceClock(14);
  const t15 = Math.floor(fakeNowMs / 1000);
  const ref15 = await refTOTP(SECRET, { timestamp: t15, period: 15, digits: 6, algo: 'SHA-1' });
  await waitFor(() => codeFor('totp-15') === ref15, 5000, 100);
  cardFor('totp-15').querySelector('.btn-copy-code').click();
  await sleep(200);
  check('15s account refreshes and copies its current window', codeFor('totp-15') === ref15 && codeFor('totp-15') !== initialCodes['totp-15'] && clipboardCalls.at(-1) === ref15,
    `displayed=${codeFor('totp-15')} copied=${clipboardCalls.at(-1)} expected=${ref15}`);

  await advanceClock(15);
  await advanceClock(15);
  const t55 = Math.floor(fakeNowMs / 1000);
  const ref30 = await refTOTP(SECRET, { timestamp: t55, period: 30, digits: 8, algo: 'SHA-256' });
  const ref45 = await refTOTP(SECRET, { timestamp: t55, period: 45, digits: 6, algo: 'SHA-512' });
  const ref60 = await refTOTP(SECRET, { timestamp: t55, period: 60, digits: 8, algo: 'SHA-1' });
  const refDecoder = await refTOTP(SECRET, { timestamp: t55, period: 45, digits: 6, algo: 'SHA-512' });
  await waitFor(() => codeFor('totp-45') === ref45 && b4.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '') === refDecoder, 5000, 100);
  cardFor('totp-45').querySelector('.btn-copy-code').click();
  await sleep(200);
  check('30s and 45s accounts refresh at their own windows', codeFor('totp-30') === ref30 && codeFor('totp-45') === ref45 && clipboardCalls.at(-1) === ref45,
    `30s=${codeFor('totp-30')} 45s=${codeFor('totp-45')} copied=${clipboardCalls.at(-1)}`);
  check('60s account and decoder refresh at their own windows', codeFor('totp-60') === ref60 && b4.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '') === refDecoder,
    `60s=${codeFor('totp-60')} decoder=${b4.document.getElementById('decLiveCode').textContent}`);
  check('global badge is not a hard-coded 30s claim', b4.document.getElementById('globalCountdownSec')?.textContent === 'LIVE');
  check('vault heading does not hard-code HMAC-SHA1', !b4.document.querySelector('[data-i18n="vault_subheading"]')?.textContent.includes('HMAC-SHA1'));
  b4.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 5: REL-002 — invalid secrets are rejected, never silently wrong ===');
{
  const { dom, document } = await boot();
  document.getElementById('quickAdd2FABtn').click();
  document.getElementById('modalIssuer').value = 'Bad';
  document.getElementById('modalAccount').value = 'x@y.io';
  document.getElementById('modalSecret').value = 'JBSWY3DPEHPK3P0P'; // contains 0
  document.getElementById('confirmAdd2FABtn').click();
  await sleep(200);
  const count = dom.window.document.querySelectorAll('.totp-card').length;
  check('secret with invalid char "0" rejected with error toast',
    count === 0 && /A–Z/.test(lastToast(document)), lastToast(document));
  dom.window.close();

  // A legacy entry with a garbage secret is rejected as a recovery case rather
  // than being silently reinterpreted as a valid account.
  const boot3 = await boot({
    preSeed: (w) => {
      w.localStorage.setItem('aeropad_notes', '[]');
      w.localStorage.setItem('aeropad_totp', JSON.stringify([{
        id: 'totp-garbage', issuer: 'G', account: 'g@x.io', secret: '0000000000', digits: 6, period: 30, algo: 'SHA1'
      }]));
    },
  });
  await sleep(300);
  const codeTxt = boot3.document.getElementById('lockOverlay');
  check('garbage secret requires recovery (no fake code)', codeTxt && !codeTxt.classList.contains('hidden'));
  boot3.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 6: UX-001 + LOGIC-001 — delete confirmation and unique IDs ===');
{
  const { dom, document } = await boot();
  for (let i = 0; i < 2; i++) {
    document.getElementById('quickAdd2FABtn').click();
    document.getElementById('modalIssuer').value = 'X' + i;
    document.getElementById('modalAccount').value = 'a@b.io';
    document.getElementById('modalSecret').value = SECRET;
    document.getElementById('confirmAdd2FABtn').click();
    await sleep(50);
  }
  await sleep(300);
  const cards = () => [...dom.window.document.querySelectorAll('.totp-card')];
  const ids = cards().map(card => card.dataset.accId);
  check('two adds land exactly two accounts', cards().length === 2,
    cards().map(card => card.textContent).join(','));
  check('same-millisecond adds get unique IDs', new Set(ids).size === ids.length, ids.join(', '));

  confirmResponses = [false];
  document.querySelector('.delete-totp-btn').click();
  await sleep(200);
  check('declined confirm keeps the account', cards().length === 2);

  confirmResponses = [true];
  document.querySelector('.delete-totp-btn').click();
  await sleep(300);
  check('accepted confirm removes exactly that account', cards().length === 1, `remaining=${cards().length}`);
  check('accepted TOTP delete uses TOTP-specific copy', lastToast(document).includes('2FA') && !lastToast(document).includes('Note deleted'), lastToast(document));
  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 7: SEC-003 generator — QR URI includes algorithm; save persists algo ===');
{
  const { dom, document } = await boot();
  document.querySelector('.nav-pill[data-tab="totp"]').click();
  document.querySelector('.totp-subpill[data-subtab="generator"]').click();
  document.getElementById('genIssuer').value = 'GenTest';
  document.getElementById('genAccount').value = 'g@t.io';
  document.getElementById('genSecret').value = SECRET;
  document.getElementById('genAlgo').value = 'SHA256';
  document.getElementById('genSecret').dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  await sleep(200);

  const uri = dom.window.eval('getOtpAuthURI()');
  check('generated otpauth URI includes algorithm=SHA256', /algorithm=SHA256/.test(uri), uri);

  document.getElementById('saveToVaultBtn').click();
  await sleep(300);
  const ref = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000), algo: 'SHA-256' });
  const cardTxt = document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  check('generator save persists and computes SHA-256 code', cardTxt === ref, `card="${cardTxt}" ref="${ref}"`);
  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 8: aeropad-standalone.html boots and computes correctly ===');
{
  const standalone = readFileSync(rootPath('aeropad-standalone.html'), 'utf8');
  const dom = new JSDOM(standalone, {
    url: 'http://localhost:8901/aeropad-standalone.html',
    runScripts: 'outside-only',
    pretendToBeVisual: true,
  });
  setupWindow(dom.window);
  const m = standalone.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
  dom.window.eval(m[1]);
  await new Promise((resolve) => {
    if (dom.window.document.readyState !== 'loading') return resolve();
    dom.window.document.addEventListener('DOMContentLoaded', resolve, { once: true });
  });
  await sleep(100);

  const d = dom.window.document;
  d.getElementById('quickAdd2FABtn').click();
  d.getElementById('modalIssuer').value = 'SA';
  d.getElementById('modalAccount').value = 's@a.io';
  d.getElementById('modalSecret').value = SECRET;
  d.getElementById('confirmAdd2FABtn').click();
  await sleep(300);
  const ref = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000) });
  const cardTxt = d.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  check('standalone artifact computes the correct code', cardTxt === ref, `card="${cardTxt}" ref="${ref}"`);
  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 9: AES-256-GCM vault encryption lifecycle ===');
{
  const MASTER_PW = 'correct horse battery staple';
  const indexedDB = makeIndexedDBHarness();

  // 9a — legacy in-memory data is migrated into one encrypted v2 record
  const b1 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  b1.document.getElementById('quickAdd2FABtn').click();
  b1.document.getElementById('modalIssuer').value = 'EncTest';
  b1.document.getElementById('modalAccount').value = 'enc@test.io';
  b1.document.getElementById('modalSecret').value = SECRET;
  b1.document.getElementById('confirmAdd2FABtn').click();
  await sleep(300);

  b1.document.getElementById('vaultLockBtn').click(); // opens security modal
  b1.document.getElementById('secNewPassword').value = MASTER_PW;
  b1.document.getElementById('secConfirmPassword').value = MASTER_PW;
  b1.document.getElementById('secSetPasswordBtn').click();
  const encrypted = await waitFor(() => indexedDB.records.get('current')?.generation === 1);
  const rawRecord = indexedDB.records.get('current');
  check('one v2 record is committed', encrypted && indexedDB.records.size === 1);
  check('ciphertext at rest does NOT contain the secret', !rawRecord.ciphertext.includes(SECRET));
  check('ciphertext at rest does NOT contain issuer either', !rawRecord.ciphertext.includes('EncTest'));
  check('legacy localStorage keys are removed only after v2 commit', !b1.window.localStorage.getItem('aeropad_notes') && !b1.window.localStorage.getItem('aeropad_totp'));
  b1.dom.window.close();

  // 9b — "reload" (fresh boot with same IndexedDB): lock screen and password checks
  const b2 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay = b2.document.getElementById('lockOverlay');
  check('lock overlay shown at boot when encrypted', overlay && !overlay.classList.contains('hidden'));

  b2.document.getElementById('lockPasswordInput').value = 'wrong-password';
  b2.document.getElementById('unlockVaultBtn').click();
  const wrongPwShown = await waitFor(() =>
    (b2.document.getElementById('lockError')?.textContent || '').length > 0);
  check('wrong password is rejected', wrongPwShown && !overlay.classList.contains('hidden'),
    b2.document.getElementById('lockError')?.textContent);

  b2.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b2.document.getElementById('unlockVaultBtn').click();
  const unlocked = await waitFor(() => overlay.classList.contains('hidden'));
  check('correct password unlocks the vault', unlocked);
  await waitFor(() => b2.document.querySelector('.totp-code-text')); // cards render async
  const codeAfterUnlock = b2.document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  const ref9 = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000) });
  check('TOTP code correct after unlock', codeAfterUnlock === ref9, `card="${codeAfterUnlock}" ref="${ref9}"`);
  b2.dom.window.close();

  // 9c — encryption cannot be removed back to plaintext
  const b3 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  b3.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b3.document.getElementById('unlockVaultBtn').click();
  await waitFor(() => b3.document.getElementById('lockOverlay').classList.contains('hidden'));
  b3.document.getElementById('vaultLockBtn').click();
  check('remove-encryption action is unavailable', b3.document.getElementById('secRemovePasswordBtn').classList.contains('hidden'));
  check('v2 record remains the only durable vault', indexedDB.records.size === 1 && !b3.window.localStorage.getItem('aeropad_totp'));
  b3.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 10: drag & drop QR image → jsQR decode → accurate fields & code ===');
{
  // Build a REAL QR code (qrcode-generator, same lib the app uses) carrying an
  // otpauth URI with non-default params
  const DROP_URI = `otpauth://totp/QRDrop:user@qr.io?secret=${SECRET}&issuer=QRDrop&digits=8&period=60&algorithm=SHA256`;
  const qr = qrcodeLib(0, 'M');
  qr.addData(DROP_URI);
  qr.make();
  const COUNT = qr.getModuleCount();
  const SCALE = 8, QUIET = 4;

  // Faithful browser-API fakes for what jsdom lacks: Image loading + canvas
  // pixel extraction. jsQR (real) then decodes the exact pixels the app feeds it.
  const b10 = await boot({
    fakes: (w) => {
      const size = (COUNT + QUIET * 2) * SCALE;
      w.Image = class {
        constructor() { this.width = 0; this.height = 0; }
        set src(v) {
          this.width = size;
          this.height = size;
          setTimeout(() => this.onload && this.onload(), 0);
        }
      };
      w.HTMLCanvasElement.prototype.getContext = function () {
        return {
          drawImage: () => {},
          getImageData: (x, y, cw, ch) => {
            const data = new w.Uint8ClampedArray(cw * ch * 4);
            for (let py = 0; py < ch; py++) {
              for (let px = 0; px < cw; px++) {
                const mx = Math.floor(px / SCALE) - QUIET;
                const my = Math.floor(py / SCALE) - QUIET;
                const dark = mx >= 0 && my >= 0 && mx < COUNT && my < COUNT && qr.isDark(my, mx);
                const v = dark ? 0 : 255;
                const i = (py * cw + px) * 4;
                data[i] = v; data[i + 1] = v; data[i + 2] = v; data[i + 3] = 255;
              }
            }
            return { data, width: cw, height: ch };
          }
        };
      };
    },
  });
  b10.window.eval(jsqrSource); // the page's real jsQR dependency

  b10.document.querySelector('.nav-pill[data-tab="totp"]').click();
  b10.document.querySelector('.totp-subpill[data-subtab="decoder"]').click();

  // Simulate the drop with a File on the drop zone
  const file = new b10.window.File([new Uint8Array([1, 2, 3])], 'qr.png', { type: 'image/png' });
  const dropEvent = new b10.window.Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(dropEvent, 'dataTransfer', { value: { files: [file] } });
  b10.document.getElementById('qrDropZone').dispatchEvent(dropEvent);

  const decoded = await waitFor(() =>
    b10.document.getElementById('decSecret')?.value === SECRET);
  check('QR drop → secret extracted correctly', decoded,
    b10.document.getElementById('decSecret')?.value);
  check('QR drop → issuer extracted', b10.document.getElementById('decIssuer')?.value === 'QRDrop');
  check('QR drop → account extracted', b10.document.getElementById('decAccount')?.value === 'user@qr.io');

  const liveOk10 = await waitFor(() => /^\d{8}$/.test(
    b10.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '')));
  const live = b10.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '');
  const ref10 = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000), period: 60, digits: 8, algo: 'SHA-256' });
  check('QR drop → live code accurate (SHA-256/60s/8-digit)', liveOk10 && live === ref10,
    `live="${live}" ref="${ref10}"`);

  b10.document.getElementById('addDecodedToVaultBtn').click();
  await waitFor(() => b10.document.querySelector('.totp-code-text'));
  check('QR drop → saved account carries digits=8/period=60/algo=SHA256',
    /^\d{4}\s\d{4}$/.test(b10.document.querySelector('.totp-code-text')?.textContent || '') &&
      b10.document.querySelector('.totp-card-footer')?.textContent.includes('60s'),
    b10.document.querySelector('.totp-card-footer')?.textContent);
  const card10 = b10.document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  check('QR drop → vault card code matches reference', card10 === ref10, `card="${card10}"`);
  b10.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 10b: QR decoding bounds oversized image work ===');
{
  const canvasEdges = [];
  const b10b = await boot({
    fakes: (w) => {
      w.Image = class {
        constructor() { this.width = 0; this.height = 0; }
        set src(v) {
          this.width = 4096;
          this.height = 3072;
          setTimeout(() => this.onload && this.onload(), 0);
        }
      };
      w.HTMLCanvasElement.prototype.getContext = function () {
        return {
          drawImage: () => {},
          getImageData: (x, y, width, height) => {
            canvasEdges.push({ width, height });
            return { data: new w.Uint8ClampedArray(4), width, height };
          }
        };
      };
    }
  });
  b10b.document.querySelector('.nav-pill[data-tab="totp"]').click();
  b10b.document.querySelector('.totp-subpill[data-subtab="decoder"]').click();
  const file = new b10b.window.File([new Uint8Array([1])], 'oversized.png', { type: 'image/png' });
  const dropEvent = new b10b.window.Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(dropEvent, 'dataTransfer', { value: { files: [file] } });
  b10b.document.getElementById('qrDropZone').dispatchEvent(dropEvent);
  const processed = await waitFor(() => canvasEdges.length > 0);
  const edge = canvasEdges[0];
  check('oversized QR canvas is bounded to a 2048px longest edge',
    processed && Math.max(edge.width, edge.height) <= 2048,
    JSON.stringify(edge));
  b10b.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 11: "2FA Account Information" fields accept manual input ===');
{
  const b11 = await boot();
  b11.document.querySelector('.nav-pill[data-tab="totp"]').click();
  b11.document.querySelector('.totp-subpill[data-subtab="decoder"]').click();

  const iss = b11.document.getElementById('decIssuer');
  const acc = b11.document.getElementById('decAccount');
  const sec = b11.document.getElementById('decSecret');
  check('decoder fields are editable inputs',
    iss?.tagName === 'INPUT' && acc?.tagName === 'INPUT' && sec?.tagName === 'INPUT');

  // Manual entry (no QR, no URI): type issuer/account/secret directly
  iss.value = 'Manual Bank';
  iss.dispatchEvent(new b11.window.Event('input', { bubbles: true }));
  acc.value = 'me@bank.io';
  acc.dispatchEvent(new b11.window.Event('input', { bubbles: true }));
  sec.value = SECRET.toLowerCase(); // sloppy typing: cleanup should handle it
  sec.dispatchEvent(new b11.window.Event('input', { bubbles: true }));

  const liveOk = await waitFor(() => {
    const t = b11.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '');
    return /^\d{6}$/.test(t);
  });
  const live11 = b11.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '');
  const ref11 = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000) });
  check('manual typing → live code correct', liveOk && live11 === ref11,
    `live="${live11}" ref="${ref11}"`);

  // Invalid secret while typing → no fake code
  sec.value = 'SHORT';
  sec.dispatchEvent(new b11.window.Event('input', { bubbles: true }));
  await waitFor(() => b11.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '') === '------');
  check('invalid manual secret → live code shows ------',
    b11.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '') === '------');

  // Fix the secret back and save — the typed issuer/account must persist
  sec.value = SECRET;
  sec.dispatchEvent(new b11.window.Event('input', { bubbles: true }));
  await waitFor(() => /^\d{6}$/.test(b11.document.getElementById('decLiveCode').textContent.replace(/\s+/g, '')));
  b11.document.getElementById('addDecodedToVaultBtn').click();
  await waitFor(() => b11.document.querySelector('.totp-code-text'));
  check('manual entry → saved with typed issuer/account',
    b11.document.querySelector('.totp-card')?.textContent.includes('Manual Bank') &&
      b11.document.querySelector('.totp-card')?.textContent.includes('me@bank.io'),
    b11.document.querySelector('.totp-card')?.textContent);
  b11.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 12: IndexedDB current-record transaction survives reload and abort ===');
{
  const indexedDB = makeIndexedDBHarness();
  const b12 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const first = { id: 'current', generation: 11, ciphertext: 'first' };
  const adapter = new IndexedDBVaultAdapter({ indexedDB: b12.window.indexedDB, databaseName: 'e2e-vault' });
  await adapter.putCurrent(first);
  const reloaded = new IndexedDBVaultAdapter({ indexedDB: b12.window.indexedDB, databaseName: 'e2e-vault' });
  check('IndexedDB reload reads the current generation', (await reloaded.getCurrent())?.generation === 11);
  check('IndexedDB contains exactly one current record', indexedDB.records.size === 1);
  indexedDB.failNext = true;
  let aborted = false;
  try { await reloaded.putCurrent({ id: 'current', generation: 12, ciphertext: 'second' }); } catch { aborted = true; }
  check('failed IndexedDB transaction rejects', aborted);
  check('failed transaction preserves previous generation', (await reloaded.getCurrent())?.generation === 11);
  b12.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 13: legacy migration preserves ambiguous browser storage ===');
{
  const legacyDom = new JSDOM('', { url: 'http://localhost:8901/migration.html' });
  const legacyStorage = legacyDom.window.localStorage;
  const rawNotes = JSON.stringify([{ id: 'n1', title: 'legacy', content: 'keep', updatedAt: 1 }]);
  legacyStorage.setItem('aeropad_notes', rawNotes);
  const oneSided = await readLegacyVault(legacyStorage);
  check('one-sided legacy data requires recovery', oneSided.state === 'legacy-recovery-required' && oneSided.reason === 'one-sided');
  check('one-sided raw notes remain untouched', legacyStorage.getItem('aeropad_notes') === rawNotes);
  legacyStorage.setItem('aeropad_totp', '[]');
  legacyStorage.setItem('aeropad_notes_corrupt_backup', 'secret residue');
  const withBackup = await readLegacyVault(legacyStorage);
  check('plaintext corrupt backup requires recovery', withBackup.reason === 'plaintext-corrupt-backup');
  check('corrupt backup remains until v2 commit', legacyStorage.getItem('aeropad_notes_corrupt_backup') === 'secret residue');
  legacyDom.window.close();
}

// ============================================================
console.log('\n=== TEST 14: v2 vault lifecycle uses one encrypted IndexedDB snapshot ===');
{
  const MASTER_PW = 'v2 lifecycle password';
  const indexedDB = makeIndexedDBHarness();
  const initialPayload = {
    schemaVersion: 2,
    notes: [{ id: 'note-v2', title: 'Before', content: 'keep this', tags: [], updatedAt: 1755800000000 }],
    totpAccounts: [{ id: 'totp-v2', issuer: 'V2', account: 'before@example.io', secret: SECRET, password: '', digits: 6, period: 30, algo: 'SHA1' }],
    metadata: { createdAt: 1755800000000, updatedAt: 1755800000000 }
  };
  indexedDB.records.set('current', await encryptVault(initialPayload, MASTER_PW, { generation: 1, crypto: webcrypto }));

  const b14 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay = b14.document.getElementById('lockOverlay');
  check('v2 record shows lock overlay at boot', overlay && !overlay.classList.contains('hidden'));
  b14.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b14.document.getElementById('unlockVaultBtn').click();
  const unlocked14 = await waitFor(() => overlay.classList.contains('hidden'));
  check('v2 record unlocks', unlocked14, b14.document.getElementById('lockError')?.textContent || 'no unlock error');

  b14.document.getElementById('newNoteBtn').click();
  b14.document.getElementById('noteTitle').value = 'After';
  b14.document.getElementById('noteContent').value = 'saved in one snapshot';
  b14.document.getElementById('noteContent').dispatchEvent(new b14.window.Event('input', { bubbles: true }));
  b14.document.getElementById('quickAdd2FABtn').click();
  b14.document.getElementById('modalIssuer').value = 'V2 Added';
  b14.document.getElementById('modalAccount').value = 'after@example.io';
  b14.document.getElementById('modalSecret').value = SECRET;
  b14.document.getElementById('confirmAdd2FABtn').click();
  const committed = await waitFor(() => indexedDB.records.get('current')?.generation === 2);
  const recordAfter = indexedDB.records.get('current');
  const payloadAfter = await decryptVault(recordAfter, MASTER_PW, { crypto: webcrypto });
  check('note and TOTP edits commit as one v2 generation', committed && payloadAfter.notes.some(note => note.content === 'saved in one snapshot') && payloadAfter.totpAccounts.some(account => account.account === 'after@example.io'));
  check('v2 save never creates legacy durable keys', !b14.window.localStorage.getItem('aeropad_notes') && !b14.window.localStorage.getItem('aeropad_totp'));
  check('IndexedDB contains one encrypted current record', indexedDB.records.size === 1 && typeof recordAfter.ciphertext === 'string' && !recordAfter.ciphertext.includes(SECRET));

  indexedDB.failNext = true;
  b14.document.getElementById('newNoteBtn').click();
  await waitFor(() => b14.document.getElementById('saveIndicator')?.dataset.state === 'save-failed');
  check('failed v2 commit preserves the previous generation', indexedDB.records.get('current')?.generation === 2);
  b14.dom.window.close();

  const b15 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlayReload = b15.document.getElementById('lockOverlay');
  b15.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b15.document.getElementById('unlockVaultBtn').click();
  check('v2 snapshot reloads and unlocks', await waitFor(() => overlayReload.classList.contains('hidden')));
  const reloadedData = await waitFor(() => b15.document.getElementById('noteTitle')?.value === 'After' && b15.document.querySelectorAll('.totp-card').length >= 2, 5000, 100);
  check('reloaded note and TOTP data are present', reloadedData, `title=${b15.document.getElementById('noteTitle')?.value} totp=${b15.document.querySelectorAll('.totp-card').length}`);
  b15.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 15: save state, flush-before-lock, and inactivity cleanup ===');
{
  const MASTER_PW = 'flush and auto lock password';
  const indexedDB = makeIndexedDBHarness();
  const initialPayload = {
    schemaVersion: 2,
    notes: [{ id: 'note-15', title: 'Pending', content: 'before', tags: [], updatedAt: 1755800000000 }],
    totpAccounts: [{ id: 'totp-15', issuer: 'Cleanup', account: 'cleanup@example.io', secret: SECRET, password: 'account-pass', digits: 6, period: 30, algo: 'SHA1' }],
    metadata: { createdAt: 1755800000000, updatedAt: 1755800000000 }
  };
  indexedDB.records.set('current', await encryptVault(initialPayload, MASTER_PW, { generation: 1, crypto: webcrypto }));

  const b16 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay16 = b16.document.getElementById('lockOverlay');
  b16.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b16.document.getElementById('unlockVaultBtn').click();
  check('flush test vault unlocks', await waitFor(() => overlay16.classList.contains('hidden')));

  const title16 = b16.document.getElementById('noteTitle');
  indexedDB.holdNext = true;
  title16.value = 'Pending save';
  title16.dispatchEvent(new b16.window.Event('input', { bubbles: true }));
  check('save indicator reports pending', await waitFor(() => b16.document.getElementById('saveIndicator')?.dataset.state === 'pending'));
  check('test harness holds the pending write', await waitFor(() => indexedDB.heldPut !== null));

  b16.document.getElementById('vaultLockBtn').click();
  const lockNow = b16.document.getElementById('secLockNowBtn');
  lockNow.click();
  await sleep(100);
  check('lock waits for pending durable write', overlay16.classList.contains('hidden'));
  check('lock action is disabled while flushing', lockNow.disabled);
  indexedDB.releaseHeld();
  check('save indicator reports committed', await waitFor(() => b16.document.getElementById('saveIndicator')?.dataset.state === 'committed'));
  check('lock completes after flush', await waitFor(() => !overlay16.classList.contains('hidden')));
  check('lock clears password input', b16.document.getElementById('lockPasswordInput').value === '');
  b16.dom.window.close();

  const b17 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay17 = b17.document.getElementById('lockOverlay');
  b17.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b17.document.getElementById('unlockVaultBtn').click();
  check('auto-lock test vault unlocks', await waitFor(() => overlay17.classList.contains('hidden')));
  await waitFor(() => b17.document.querySelector('.toggle-card-pass'));
  b17.document.querySelector('.toggle-card-pass').click();
  check('password reveal is visible before lock', b17.document.querySelector('.pass-masked-val')?.textContent === 'account-pass');
  b17.document.getElementById('vaultLockBtn').click();
  b17.document.getElementById('secCurrentPassword').value = 'transient-password';
  Object.defineProperty(b17.document, 'visibilityState', { value: 'visible', configurable: true });
  fakeNowMs += (15 * 60 * 1000) + 1000;
  b17.document.dispatchEvent(new b17.window.Event('visibilitychange'));
  check('visibility return auto-locks after inactivity', await waitFor(() => !overlay17.classList.contains('hidden')));
  check('auto-lock clears revealed and form secrets', b17.document.getElementById('secCurrentPassword').value === '' && !b17.document.body.textContent.includes('account-pass'));
  b17.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 16: encrypted .aeropad backup export and restore ===');
{
  const MASTER_PW = 'portable backup password';
  const indexedDB = makeIndexedDBHarness();
  const initialPayload = {
    schemaVersion: 2,
    notes: [{ id: 'note-16', title: 'Portable', content: 'backup me', tags: [], updatedAt: 1755800000000 }],
    totpAccounts: [{ id: 'totp-16', issuer: 'Backup', account: 'backup@example.io', secret: SECRET, password: 'backup-account-pass', digits: 6, period: 30, algo: 'SHA1' }],
    metadata: { createdAt: 1755800000000, updatedAt: 1755800000000 }
  };
  indexedDB.records.set('current', await encryptVault(initialPayload, MASTER_PW, { generation: 4, crypto: webcrypto }));

  const b18 = await boot({ fakes: w => { Object.defineProperty(w, 'indexedDB', { value: indexedDB, configurable: true }); } });
  const overlay18 = b18.document.getElementById('lockOverlay');
  b18.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b18.document.getElementById('unlockVaultBtn').click();
  check('backup test vault unlocks', await waitFor(() => overlay18.classList.contains('hidden')));
  b18.document.getElementById('vaultLockBtn').click();
  b18.document.getElementById('exportBackupBtn').click();
  check('backup export creates a download', await waitFor(() => backupDownloads.length === 1));
  const backupText = await blobText(backupDownloads[0], b18.window);
  const backupFile = JSON.parse(backupText);
  check('backup has the specified format and checksum', backupFile.format === 'aeropad-backup' && backupFile.version === 1 && /^[a-f0-9]{64}$/.test(backupFile.checksum.value));
  check('backup export never contains plaintext vault data', !backupText.includes(SECRET) && !backupText.includes('backup-account-pass'));

  const fileInput = b18.document.getElementById('backupFileInput');
  const file = new b18.window.File([backupText], 'vault.aeropad', { type: 'application/json' });
  Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
  fileInput.dispatchEvent(new b18.window.Event('change', { bubbles: true }));
  b18.document.getElementById('backupRestorePassword').value = 'wrong password';
  b18.document.getElementById('backupRestorePassword').dispatchEvent(new b18.window.Event('input', { bubbles: true }));
  confirmResponses = [true];
  b18.document.getElementById('restoreBackupBtn').click();
  check('wrong backup password is rejected without replacement', await waitFor(() => b18.document.getElementById('backupStatus')?.dataset.state === 'backup-error') && indexedDB.records.get('current')?.generation === 4);

  b18.document.getElementById('backupRestorePassword').value = MASTER_PW;
  b18.document.getElementById('backupRestorePassword').dispatchEvent(new b18.window.Event('input', { bubbles: true }));
  confirmResponses = [true];
  b18.document.getElementById('restoreBackupBtn').click();
  check('correct backup restore locks the imported vault', await waitFor(() => !overlay18.classList.contains('hidden')) && indexedDB.records.get('current')?.generation === 4);
  b18.dom.window.close();
}

// ============================================================
console.log('\n=== TEST 17: SEC-004 — user-controlled toast content and dialog security UX ===');
{
  const { dom, window, document } = await boot();
  const payload = '<img src=x onerror=window.__aeroPwned=1>';
  document.getElementById('newNoteBtn').click();
  document.getElementById('noteTitle').value = payload;
  document.getElementById('noteTitle').dispatchEvent(new window.Event('input', { bubbles: true }));
  window.eval('showToast(document.getElementById("noteTitle").value, "error")');
  await sleep(50);
  const toast = [...document.querySelectorAll('.toast-item')].at(-1);
  check('user-controlled note title is rendered as text in toast',
    !!toast && !toast.querySelector('img') && !toast.querySelector('[onerror]') && toast.textContent.includes(payload));

  check('TOTP secrets are masked by default',
    ['genSecret', 'modalSecret', 'decSecret'].every(id => document.getElementById(id)?.type === 'password'));
  check('TOTP secrets have explicit reveal controls',
    ['toggleGenSecretVisibility', 'toggleModalSecretVisibility', 'toggleDecSecretVisibility'].every(id => !!document.getElementById(id)));

  const quickTrigger = document.getElementById('quickAdd2FABtn');
  quickTrigger.focus();
  quickTrigger.click();
  const quickBackdrop = document.getElementById('modalBackdrop');
  const quickDialog = quickBackdrop.querySelector('[role="dialog"]');
  check('quick add modal has dialog semantics',
    !!quickDialog && quickDialog.getAttribute('aria-modal') === 'true' && quickDialog.getAttribute('aria-labelledby'));
  check('quick add controls are label-associated',
    ['modalIssuer', 'modalAccount', 'modalSecret', 'modalPassword'].every(id => document.getElementById(id)?.labels?.length));
  if (quickDialog) {
    const focusables = [...quickDialog.querySelectorAll('button, input, select, textarea')].filter(el => !el.disabled && !el.closest('.hidden'));
    const first = focusables[0];
    const last = focusables.at(-1);
    last?.focus();
    quickBackdrop.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
    check('quick add focus trap wraps forward', document.activeElement === first);
    first?.focus();
    quickBackdrop.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true }));
    check('quick add focus trap wraps backward', document.activeElement === last);
  }
  document.getElementById('cancelModalBtn').click();
  check('quick add close returns focus to trigger', document.activeElement === quickTrigger);

  const securityTrigger = document.getElementById('vaultLockBtn');
  securityTrigger.focus();
  securityTrigger.click();
  const securityBackdrop = document.getElementById('securityModalBackdrop');
  const securityDialog = securityBackdrop.querySelector('[role="dialog"]');
  check('security modal has dialog semantics',
    !!securityDialog && securityDialog.getAttribute('aria-modal') === 'true' && securityDialog.getAttribute('aria-labelledby'));
  check('security password controls are label-associated',
    ['secNewPassword', 'secConfirmPassword', 'backupRestorePassword'].every(id => document.getElementById(id)?.labels?.length));
  document.getElementById('closeSecurityModalBtn').click();
  check('security modal close returns focus to trigger', document.activeElement === securityTrigger);
  check('lock overlay declares dialog semantics',
    document.getElementById('lockOverlay').getAttribute('role') === 'dialog' && document.getElementById('lockOverlay').getAttribute('aria-modal') === 'true');
  dom.window.close();
}

// ============================================================
const failed = results.filter(r => !r.ok);
console.log(`\n========== E2E RESULT: ${results.length - failed.length}/${results.length} PASSED ==========`);
if (failed.length) {
  console.log('FAILED:');
  failed.forEach(f => console.log('  -', f.name, f.detail));
  process.exit(1);
}
process.exit(0);
