import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json' with { type: 'json' };

export default defineConfig({
  plugins: [preact(), crx({ manifest })],
  build: {
    target: 'es2022',
    sourcemap: true,
  },
  resolve: {
    alias: { react: 'preact/compat', 'react-dom': 'preact/compat' },
  },
  test: {
    globals: true,
    environment: 'happy-dom',
    // Playwright owns the e2e directory; vitest must skip it.
    exclude: ['node_modules', 'dist', 'test/e2e/**'],
    coverage: { reporter: ['text', 'html'], thresholds: { lines: 80, branches: 80, functions: 80 } },
  },
});