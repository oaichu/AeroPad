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