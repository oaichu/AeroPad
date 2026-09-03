// Visual + DOM inspection. Serves dist/ over HTTP (avoids file:// CORS),
// opens the popup in a real Chromium with a mocked chrome.* API whose
// state is driven by ?state=no-vault|locked|unlocked.

import { chromium } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DIST = path.resolve(__dirname, '../../dist');
const SHOTS = path.resolve(__dirname, '../../.shots');
fs.mkdirSync(SHOTS, { recursive: true });

const MIME: Record<string, string> = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.map': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

function startServer(): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let p = req.url?.split('?')[0] ?? '/';
      if (p === '/') p = '/src/popup/index.html';
      const fp = path.join(DIST, p);
      if (!fp.startsWith(DIST) || !fs.existsSync(fp)) {
        res.writeHead(404); res.end('not found'); return;
      }
      const ext = path.extname(fp);
      res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream' });
      fs.createReadStream(fp).pipe(res);
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => server.close() });
    });
  });
}

const MOCK_INIT = `
(function () {
  const url = new URL(location.href);
  const want = url.searchParams.get('state') || 'no-vault';
  const seedJson = url.searchParams.get('seed');

  const state = { vaultBlob: null, key: null, vault: null };
  if (want === 'locked' || want === 'unlocked') state.vaultBlob = 'present';
  if (want === 'unlocked') {
    state.key = {};
    if (seedJson) { try { state.vault = JSON.parse(seedJson); } catch (e) { state.vault = { codes: [], notes: [] }; } }
    else state.vault = { codes: [/* ... */], notes: [/* ... */] };
  }
  if (want === 'unlocked' && seedJson) {
    try { state.vault = JSON.parse(seedJson); } catch (e) { state.vault = { codes: [], notes: [] }; }
  }
  if (want === 'unlocked' && !seedJson) {
    state.vault = { codes: [
      { id: 'a', issuer: 'GitHub', account: 'me@github.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0 },
      { id: 'b', issuer: 'Google', account: 'me@gmail.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0 },
      { id: 'c', issuer: 'AWS', account: 'root', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0 },
    ], notes: [
      { id: 'n1', title: 'Recovery codes', body: 'GitHub: 12345-67890', updatedAt: 0 },
    ] };
  }

  const handlers = {
    isUnlocked: () => !state.vaultBlob ? { ok: true, data: 'no-vault' } : (state.vault === null ? { ok: true, data: 'locked' } : { ok: true, data: 'unlocked' }),
    createVault: (m) => { if (typeof m.password !== 'string' || m.password.length < 8) return { ok: false, error: 'weak_password' }; state.vaultBlob = 'present'; state.key = {}; state.vault = { codes: [], notes: [] }; return { ok: true }; },
    unlock: () => { if (state.vault === null) state.vault = { codes: [], notes: [] }; state.key = {}; return { ok: true }; },
    lock: () => { state.vault = null; state.key = null; return { ok: true }; },
    getCodes: () => ({ ok: true, data: state.vault?.codes ?? [] }),
    getNotes: () => ({ ok: true, data: state.vault?.notes ?? [] }),
    addEntry: (m) => { if (!state.vault) return { ok: false, error: 'locked' }; const e = Object.assign({}, m.entry, { id: Math.random().toString(36).slice(2), createdAt: Date.now() }); state.vault.codes.push(e); return { ok: true, data: e }; },
    saveNote: (m) => { if (!state.vault) return { ok: false, error: 'locked' }; const i = state.vault.notes.findIndex((x) => x.id === m.note.id); if (i >= 0) state.vault.notes[i] = m.note; else state.vault.notes.push(m.note); return { ok: true }; },
    deleteEntry: (m) => { if (!state.vault) return { ok: false, error: 'locked' }; state.vault.codes = state.vault.codes.filter((c) => c.id !== m.id); return { ok: true }; },
    updateEntry: (m) => { if (!state.vault) return { ok: false, error: 'locked' }; const i = state.vault.codes.findIndex((c) => c.id === m.id); if (i >= 0) Object.assign(state.vault.codes[i], m.patch); return { ok: true }; },
    deleteNote: (m) => { if (!state.vault) return { ok: false, error: 'locked' }; state.vault.notes = state.vault.notes.filter((n) => n.id !== m.id); return { ok: true }; },
  };

  globalThis.chrome = {
    runtime: {
      sendMessage: (msg) => Promise.resolve(handlers[msg.kind] ? handlers[msg.kind](msg) : { ok: false, error: 'unknown' }),
      openOptionsPage: () => Promise.resolve(),
    },
    storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve(), remove: () => Promise.resolve() } },
  };
})();
`;

async function main() {
  const srv = await startServer();
  console.log(`Serving ${DIST} on ${srv.url}`);

  const browser = await chromium.launch({ headless: true });
  const issues: string[] = [];

  async function inspect(label: string, urlPath: string, viewport: { width: number; height: number }) {
    const context = await browser.newContext({ viewport });
    await context.addInitScript(MOCK_INIT);
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(`console.error: ${m.text()}`); });
    await page.goto(`${srv.url}${urlPath}`);
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(SHOTS, `${label}.png`), fullPage: true });
    const body = (await page.locator('body').innerText()).trim();
    const dims = await page.evaluate(() => {
      const r = document.documentElement.getBoundingClientRect();
      return { w: Math.round(r.width), h: Math.round(r.height), sw: document.documentElement.scrollWidth, sh: document.documentElement.scrollHeight, vw: window.innerWidth, vh: window.innerHeight };
    });
    const inputCount = await page.locator('input').count();
    const buttonCount = await page.locator('button').count();
    const domIssues = await page.evaluate(() => {
      const issues = [];
      const all = document.querySelectorAll('*');
      for (const el of all) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && el.scrollWidth > r.width + 1 && getComputedStyle(el).overflow === 'hidden') {
          issues.push(`${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]} clips content (scrollW=${el.scrollWidth} > w=${Math.round(r.width)})`);
        }
      }
      if (document.documentElement.scrollWidth > window.innerWidth + 1) {
        issues.push(`PAGE HORIZONTAL OVERFLOW: scrollW=${document.documentElement.scrollWidth} > viewport=${window.innerWidth}`);
      }
      // Check that interactive elements are inside the viewport
      const interactive = document.querySelectorAll('input, button, select, textarea, a');
      for (const el of interactive) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) issues.push(`${el.tagName.toLowerCase()} has 0 size`);
        if (r.right > window.innerWidth + 1) issues.push(`${el.tagName.toLowerCase()} extends past right edge (right=${Math.round(r.right)} > vw=${window.innerWidth})`);
        if (r.bottom > window.innerHeight + 1) issues.push(`${el.tagName.toLowerCase()} extends past bottom (bottom=${Math.round(r.bottom)} > vh=${window.innerHeight})`);
      }
      return issues;
    });
    console.log(`\n=== ${label} (${urlPath}, viewport ${viewport.width}x${viewport.height}) ===`);
    console.log(`  body: ${JSON.stringify(body.slice(0, 350))}`);
    console.log(`  dims: ${JSON.stringify(dims)} inputs=${inputCount} buttons=${buttonCount}`);
    if (domIssues.length) {
      console.log(`  ISSUES: ${domIssues.join(' | ')}`);
      issues.push(...domIssues.map((s) => `${label}: ${s}`));
    }
    if (errors.length) {
      const real = errors.filter((e) => !e.includes('CORS') && !e.includes('ERR_FAILED') && !e.includes('__name'));
      if (real.length) {
        console.log(`  ERRORS: ${real.join(' | ')}`);
        issues.push(...real.map((s) => `${label}: ${s}`));
      }
    }
    await context.close();
  }

  // Popup at standard 360px width and 600px height (typical extension popup)
  await inspect('01-popup-no-vault', '/src/popup/index.html?state=no-vault', { width: 360, height: 600 });
  await inspect('02-popup-locked', '/src/popup/index.html?state=locked', { width: 360, height: 600 });
  await inspect('03-popup-unlocked', '/src/popup/index.html?state=unlocked', { width: 360, height: 600 });
  // Popup at narrowest realistic
  await inspect('04-popup-narrow', '/src/popup/index.html?state=unlocked', { width: 320, height: 480 });
  // Options page
  await inspect('05-options', '/src/options/options.html?state=unlocked', { width: 800, height: 1000 });

  await browser.close();
  srv.close();

  console.log(`\n========= SUMMARY =========`);
  console.log(`Total issues: ${issues.length}`);
  for (const i of issues) console.log(`  - ${i}`);
  console.log(`Screenshots: ${SHOTS}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
