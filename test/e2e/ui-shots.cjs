const { chromium } = require('@playwright/test');
const path = require('path');
const dist = path.resolve(__dirname, '../../dist');

(async () => {
  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: true,
    colorScheme: 'dark',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  let sw = context.serviceWorkers()[0];
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
  const id = new URL(sw.url()).host;

  const popup = await context.newPage();
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${id}/src/popup/index.html`);
  await popup.waitForTimeout(800);
  await popup.screenshot({ path: '/tmp/ext-1-createvault.png' });

  // create vault
  const pw = 'ui-shot-password';
  await popup.locator('input[type="password"]').first().fill(pw);
  const confirm = popup.locator('input[type="password"]').nth(1);
  if (await confirm.isVisible()) await confirm.fill(pw);
  await popup.getByRole('button', { name: /create|protect|unlock/i }).first().click();
  await popup.waitForTimeout(1200);
  await popup.screenshot({ path: '/tmp/ext-2-empty.png' });

  // add two entries + a note
  await popup.evaluate(async () => {
    await chrome.runtime.sendMessage({ kind: 'addEntry', entry: { issuer: 'GitHub', account: 'oaichu@github.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    await chrome.runtime.sendMessage({ kind: 'addEntry', entry: { issuer: 'Google', account: 'oaichu@gmail.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8, period: 30 } });
    await chrome.runtime.sendMessage({ kind: 'saveNote', note: { id: 'n1', title: 'Recovery codes', body: 'github: xxxx-xxxx', updatedAt: Date.now() } });
  });
  await popup.reload();
  await popup.waitForTimeout(1000);
  const pwField = popup.locator('input[type="password"]').first();
  if (await pwField.isVisible().catch(() => false)) {
    await pwField.fill(pw);
    await popup.getByRole('button', { name: /unlock|create|protect/i }).first().click();
    await popup.waitForTimeout(1500);
  }
  await popup.screenshot({ path: '/tmp/ext-3-codes.png' });

  // options page
  const opt = await context.newPage();
  await opt.setViewportSize({ width: 900, height: 700 });
  await opt.goto(`chrome-extension://${id}/src/options/options.html`);
  await opt.waitForTimeout(1000);
  await opt.screenshot({ path: '/tmp/ext-4-options.png' });

  await context.close();
  console.log('done');
})().catch((e) => { console.error(e); process.exit(1); });
