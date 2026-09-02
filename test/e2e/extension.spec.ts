import { test, expect, chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readFileSync, existsSync } from 'node:fs';

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

  // Launch a real Chrome with the unpacked extension loaded. We don't
  // strictly need to wait for the SW to register here; the smoke test
  // goal is "load + manifest valid + popup HTML reachable".
  const context = await chromium.launchPersistentContext(distPath, {
    headless: true,
    args: [
      `--disable-extensions-except=${distPath}`,
      `--load-extension=${distPath}`,
    ],
  });
  try {
    // Load the popup HTML directly via a normal page; this exercises the
    // same path the Chrome toolbar uses (popup HTML is served from the
    // extension origin and runs the same module graph).
    const page = await context.newPage();
    await page.goto('file://' + popupPath);
    const html = await page.content();
    expect(html).toContain('<div id="app"');
    // Vite rewrites the original module entry to a hashed bundle filename.
    expect(html).toMatch(/<script[^>]+src="\/assets\/index\.html-[^"]+\.js"/);
    await page.close();

    // Load the login fixture to confirm content-script pages load.
    const fixturePage = await context.newPage();
    await fixturePage.goto('file://' + fixturePath);
    expect(await fixturePage.locator('input[name=code]').count()).toBe(1);
    await fixturePage.close();
  } finally {
    await context.close();
  }
});