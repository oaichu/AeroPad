import { test, expect, chromium } from '@playwright/test';
import type { BrowserContext } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const here = path.dirname(fileURLToPath(import.meta.url));
const distPath = path.resolve(here, '../../dist');
const manifestPath = path.join(distPath, 'manifest.json');
const fixturePath = path.resolve(here, '../fixtures/login-page.html');

test('unpacked extension loads: manifest is valid and popup HTML is reachable', async () => {
  // Pre-flight: build artifact exists and has a parseable manifest.
  expect(existsSync(manifestPath), `expected ${manifestPath} to exist`).toBe(true);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  expect(manifest.manifest_version).toBe(3);
  expect(manifest.name).toBe('AeroPad');
  expect(Array.isArray(manifest.permissions)).toBe(true);
  expect(typeof manifest.background?.service_worker).toBe('string');

  // Popup HTML file the manifest points at must exist on disk.
  const popupRel = manifest.action?.default_popup;
  expect(typeof popupRel).toBe('string');
  const popupPath = path.join(distPath, popupRel as string);
  expect(existsSync(popupPath), `expected popup HTML at ${popupPath}`).toBe(true);

  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: true,
    args: [
      `--disable-extensions-except=${distPath}`,
      `--load-extension=${distPath}`,
    ],
  });
  try {
    const page = await context.newPage();
    await page.goto('file://' + popupPath);
    const html = await page.content();
    expect(html).toContain('<div id="app"');
    expect(html).toMatch(/<script[^>]+src="\/assets\/index\.html-[^"]+\.js"/);
    await page.close();
  } finally {
    await context.close();
  }
});

// Full functional flow in real Chromium: load unpacked MV3 extension, create
// a vault through the real popup UI, add a 2FA entry, then verify the content
// script injects its fill button on a served login page and fills the code.
test.describe('extension end-to-end (real browser)', () => {
  let context: BrowserContext;
  let server: Server;
  let baseUrl = '';
  let extensionId = '';

  test.beforeAll(async () => {
    server = createServer((_req, res) => {
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(readFileSync(fixturePath, 'utf-8'));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    context = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      headless: true,
      args: [
        `--disable-extensions-except=${distPath}`,
        `--load-extension=${distPath}`,
      ],
    });
    let sw = context.serviceWorkers()[0];
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15_000 });
    extensionId = new URL(sw.url()).host;
    expect(extensionId).toMatch(/^[a-p]{32}$/);
  });

  test.afterAll(async () => {
    await context?.close();
    server?.close();
  });

  test('create vault via real popup UI → content script fills TOTP on page', async () => {
    test.setTimeout(60_000);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);

    // First-run: CreateVaultDialog (not Unlock) must be shown.
    const pw = 'e2e-master-pw';
    await popup.locator('input[type="password"]').first().fill(pw);
    const confirmField = popup.locator('input[type="password"]').nth(1);
    if (await confirmField.isVisible()) await confirmField.fill(pw);
    await popup.getByRole('button', { name: /create|unlock|protect/i }).first().click();
    await expect(popup.getByText(/2FA Codes/i)).toBeVisible({ timeout: 10_000 });

    // Add a TOTP entry via the real message channel (popup → SW → storage).
    await popup.evaluate(async () => {
      const r = await chrome.runtime.sendMessage({
        kind: 'addEntry',
        entry: {
          issuer: '127.0.0.1',
          account: 'e2e@local.test',
          secret: 'JBSWY3DPEHPK3PXP',
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
        },
      });
      if (!r?.ok) throw new Error(`addEntry failed: ${JSON.stringify(r)}`);
    });

    // Open the fixture page over HTTP — content script runs on <all_urls>.
    const page = await context.newPage();
    await page.goto(`${baseUrl}/login`);

    // The injected fill button must appear next to the 2FA input.
    const otpInput = page.locator('input[name=code]');
    await expect(otpInput).toBeVisible();
    const fillBtn = page.locator('button[aria-label="Fill from AeroPad"]');
    await expect(fillBtn).toBeVisible({ timeout: 10_000 });

    // Click → SW matches entry for 127.0.0.1 → fill_command → value written.
    await fillBtn.click();
    await expect(otpInput).toHaveValue(/^\d{6}$/, { timeout: 10_000 });

    // Persistence check: vault blob exists in extension storage.
    const blob = await popup.evaluate(async () => {
      const r = await chrome.storage.local.get('vaultBlob');
      return r.vaultBlob ?? null;
    });
    expect(blob).toBeTruthy();
    expect(typeof blob.salt).toBe('string');
    expect(typeof blob.ciphertext).toBe('string');

    await page.close();
    await popup.close();
  });
});
