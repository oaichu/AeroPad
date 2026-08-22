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
import { JSDOM } from 'jsdom';

const require = createRequire(import.meta.url);
const qrcodeLib = require('qrcode-generator');
const jsqrSource = readFileSync('node_modules/jsqr/dist/jsQR.js', 'utf8');

const html = readFileSync('/home/oaichu/aeropad/index.html', 'utf8');
const appJs = readFileSync('/home/oaichu/aeropad/app.js', 'utf8');
const { generateTOTP: refTOTP } = await import('/home/oaichu/aeropad/src/crypto/totp.js');

const SECRET = 'JBSWY3DPEHPK3PXP';
let fakeNowMs;
let clipboardCalls = [];
let confirmResponses = [];

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
    encrypt: (alg, key, data) => webcrypto.subtle.encrypt({ name: alg.name, iv: toNodeBuffer(alg.iv) }, key, toNodeBuffer(data)),
    decrypt: (alg, key, data) => webcrypto.subtle.decrypt({ name: alg.name, iv: toNodeBuffer(alg.iv) }, key, toNodeBuffer(data)),
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
  window.confirm = () => confirmResponses.shift() ?? false;
  window.Element.prototype.scrollIntoView = () => {};
  // jsdom lacks TextEncoder/TextDecoder — the app uses them for AES payloads
  if (!window.TextEncoder) window.TextEncoder = TextEncoder;
  if (!window.TextDecoder) window.TextDecoder = TextDecoder;
}

async function boot({ preSeed, fakes } = {}) {
  fakeNowMs = 1755800000000; // arbitrary epoch, lands mid-window
  clipboardCalls = [];
  confirmResponses = [];

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
console.log('=== TEST 1: REL-001 — corrupted localStorage must not brick boot ===');
{
  const { dom, window } = await boot({
    preSeed: (w) => {
      w.localStorage.setItem('aeropad_notes', 'CORRUPTED{{{NOT JSON');
      w.localStorage.setItem('aeropad_totp', '{"broken tru');
    },
  });
  const notesBtn = window.document.getElementById('newNoteBtn');
  const backup = window.localStorage.getItem('aeropad_notes_corrupt_backup');
  check('app boots with corrupted storage', !!notesBtn, '');
  check('corrupt data backed up before reset', backup === 'CORRUPTED{{{NOT JSON', backup ?? '(null)');
  notesBtn.click();
  check('note creation works after recovery', window.document.querySelectorAll('.note-item').length === 1);
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
  const saved = JSON.parse(dom.window.localStorage.getItem('aeropad_totp'))[0];
  check('vault account carries digits=8, period=60, algo=SHA256',
    saved.digits === 8 && saved.period === 60 && saved.algo === 'SHA256',
    JSON.stringify({ digits: saved.digits, period: saved.period, algo: saved.algo }));

  const cardTxt = document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  const cardRef = await refTOTP(SECRET, {
    timestamp: Math.floor(fakeNowMs / 1000), period: 60, digits: 8, algo: 'SHA-256'
  });
  check('vault card generates the SHA-256/60s/8-digit code', cardTxt === cardRef,
    `card="${cardTxt}" ref="${cardRef}"`);

  dom.window.close();
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
  const count = JSON.parse(dom.window.localStorage.getItem('aeropad_totp') || '[]').length;
  check('secret with invalid char "0" rejected with error toast',
    count === 0 && /A–Z/.test(lastToast(document)), lastToast(document));
  dom.window.close();

  // A vault entry saved by an OLD version with a garbage secret renders "------"
  // instead of a silently-wrong code
  const boot3 = await boot({
    preSeed: (w) => w.localStorage.setItem('aeropad_totp', JSON.stringify([{
      id: 'totp-garbage', issuer: 'G', account: 'g@x.io', secret: '0000000000', digits: 6, period: 30, algo: 'SHA1'
    }])),
  });
  await sleep(300);
  const codeTxt = boot3.document.querySelector('.totp-code-text')?.textContent;
  check('garbage secret displays "------" (no fake code)', codeTxt === '------', `shown="${codeTxt}"`);
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
  const stored = JSON.parse(dom.window.localStorage.getItem('aeropad_totp'));
  const ids = stored.map(a => a.id);
  check('two adds land exactly two accounts', stored.length === 2,
    stored.map(a => a.issuer).join(','));
  check('same-millisecond adds get unique IDs', new Set(ids).size === ids.length, ids.join(', '));

  confirmResponses = [false];
  document.querySelector('.delete-totp-btn').click();
  await sleep(200);
  check('declined confirm keeps the account',
    JSON.parse(dom.window.localStorage.getItem('aeropad_totp')).length === 2);

  confirmResponses = [true];
  document.querySelector('.delete-totp-btn').click();
  await sleep(300);
  const remaining = JSON.parse(dom.window.localStorage.getItem('aeropad_totp'));
  check('accepted confirm removes exactly that account', remaining.length === 1, `remaining=${remaining.length}`);
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
  const saved = JSON.parse(dom.window.localStorage.getItem('aeropad_totp'))[0];
  check('generator save persists algo=SHA256', saved.algo === 'SHA256');

  const ref = await refTOTP(SECRET, { timestamp: Math.floor(fakeNowMs / 1000), algo: 'SHA-256' });
  const cardTxt = document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  check('vault card computes SHA-256 code for that account', cardTxt === ref, `card="${cardTxt}" ref="${ref}"`);
  dom.window.close();
}

// ============================================================
console.log('\n=== TEST 8: aeropad-standalone.html boots and computes correctly ===');
{
  const standalone = readFileSync('/home/oaichu/aeropad/aeropad-standalone.html', 'utf8');
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

  // 9a — plaintext mode: add an account, then set a master password
  const b1 = await boot();
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
  const encrypted = await waitFor(() =>
    (b1.window.localStorage.getItem('aeropad_totp') || '').includes('AES-GCM-256'));

  const rawTotp = b1.window.localStorage.getItem('aeropad_totp');
  const rawNotes = b1.window.localStorage.getItem('aeropad_notes');
  let envOk = false;
  try { envOk = JSON.parse(rawTotp).enc === 'AES-GCM-256' && JSON.parse(rawNotes).enc === 'AES-GCM-256'; } catch {}
  check('both keys stored as AES-GCM envelopes', envOk);
  check('ciphertext at rest does NOT contain the secret', !rawTotp.includes(SECRET));
  check('ciphertext at rest does NOT contain issuer either', !rawTotp.includes('EncTest'));
  b1.dom.window.close();

  // 9b — "reload" (fresh boot with same storage): lock screen, wrong password rejected
  const b2 = await boot({
    preSeed: (w) => {
      w.localStorage.setItem('aeropad_notes', rawNotes);
      w.localStorage.setItem('aeropad_totp', rawTotp);
    },
  });
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

  // 9c — remove encryption with the correct password → plaintext returns, data intact
  const b3 = await boot({
    preSeed: (w) => {
      w.localStorage.setItem('aeropad_notes', rawNotes);
      w.localStorage.setItem('aeropad_totp', rawTotp);
    },
  });
  b3.document.getElementById('lockPasswordInput').value = MASTER_PW;
  b3.document.getElementById('unlockVaultBtn').click();
  await waitFor(() => b3.document.getElementById('lockOverlay').classList.contains('hidden'));
  b3.document.getElementById('vaultLockBtn').click();
  confirmResponses = [true];
  b3.document.getElementById('secCurrentPassword').value = MASTER_PW;
  b3.document.getElementById('secRemovePasswordBtn').click();
  const backPlain = await waitFor(() => {
    try { return JSON.parse(b3.window.localStorage.getItem('aeropad_totp'))[0].secret === SECRET; } catch { return false; }
  });
  check('remove-encryption restores plaintext with data intact', backPlain);
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
  const saved10 = JSON.parse(b10.window.localStorage.getItem('aeropad_totp'))[0];
  check('QR drop → saved account carries digits=8/period=60/algo=SHA256',
    saved10.digits === 8 && saved10.period === 60 && saved10.algo === 'SHA256',
    JSON.stringify({ d: saved10.digits, p: saved10.period, a: saved10.algo }));
  const card10 = b10.document.querySelector('.totp-code-text')?.textContent.replace(/\s+/g, '');
  check('QR drop → vault card code matches reference', card10 === ref10, `card="${card10}"`);
  b10.dom.window.close();
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
  const saved11 = JSON.parse(b11.window.localStorage.getItem('aeropad_totp'))[0];
  check('manual entry → saved with typed issuer/account',
    saved11.issuer === 'Manual Bank' && saved11.account === 'me@bank.io' && saved11.secret === SECRET,
    JSON.stringify({ i: saved11.issuer, a: saved11.account }));
  b11.dom.window.close();
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
