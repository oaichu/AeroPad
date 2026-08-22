import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2] ?? 'full';
const generatedFiles = [
  'index.html',
  'styles.css',
  'app.js',
  'aeropad-standalone.html',
  '_headers',
];

function rootPath(relativePath) {
  return resolve(root, relativePath);
}

function assertCanonicalInputs() {
  const index = readFileSync(rootPath('index.html'), 'utf8');
  if (!index.includes('Generated app bundle: scripts/build.mjs -> src/app.js')) {
    throw new Error('index.html is missing the canonical src/app.js build marker');
  }
}

function assertSelfHostedRuntimeInputs() {
  const files = ['index.html', '_headers', 'vercel.json'];
  const forbidden = /cdn\.jsdelivr\.net|fonts\.googleapis\.com|fonts\.gstatic\.com|rsms\.me|unsafe-inline/;
  const violations = files.flatMap((file) => {
    const contents = readFileSync(rootPath(file), 'utf8');
    return forbidden.test(contents) ? [file] : [];
  });
  if (violations.length) {
    throw new Error(`runtime dependencies or unsafe CSP directives are not self-hosted: ${violations.join(', ')}`);
  }
  const policy = files.slice(1).map((file) => readFileSync(rootPath(file), 'utf8')).join('\n');
  if (!policy.includes("script-src 'self'") || !policy.includes("style-src 'self'")) {
    throw new Error('security headers must keep script-src and style-src self-only');
  }
}

function inlineStandaloneAssets() {
  const standalonePath = rootPath('aeropad-standalone.html');
  let standalone = readFileSync(standalonePath, 'utf8');
  const fontsCss = readFileSync(rootPath('vendor/fonts.css'), 'utf8').replace(
    /url\(['"]\.\/fonts\/([^'")]+)['"]\)/g,
    (_, file) => {
      const extension = file.split('.').pop();
      const mime = extension === 'woff2' ? 'font/woff2' : 'font/ttf';
      const data = readFileSync(rootPath(`vendor/fonts/${file}`)).toString('base64');
      return `url(data:${mime};base64,${data})`;
    },
  );
  const fontLink = '<link rel="stylesheet" href="vendor/fonts.css">';
  if (!standalone.includes(fontLink)) {
    throw new Error(`standalone asset tag not found: ${fontLink}`);
  }
  standalone = standalone.replace(fontLink, () => `<style data-aeropad-fonts>\n${fontsCss.trimEnd()}\n</style>`);

  const qrSources = [
    '  <script src="vendor/qr/qrcode-generator-2.0.4.js"></script>',
    '  <script src="vendor/qr/jsqr-1.4.0.js"></script>',
  ];
  for (const source of qrSources) {
    if (!standalone.includes(source)) {
      throw new Error(`standalone asset tag not found: ${source}`);
    }
    standalone = standalone.replace(source, () => '');
  }
  const appScript = standalone.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
  if (!appScript) {
    throw new Error('standalone app script not found');
  }
  const qrCode = readFileSync(rootPath('vendor/qr/qrcode-generator-2.0.4.js'), 'utf8');
  const jsQr = readFileSync(rootPath('vendor/qr/jsqr-1.4.0.js'), 'utf8');
  const mergedScript = `<script>\n${qrCode.trimEnd()}\n${jsQr.trimEnd()}\n${appScript[1].trimEnd()}\n</script>\n</body>`;
  standalone = standalone.replace(appScript[0], () => mergedScript);
  writeFileSync(standalonePath, standalone);
}

function inlineHashes(html, tag) {
  const pattern = tag === 'script'
    ? /<script>([\s\S]*?)<\/script>/g
    : /<style(?:\s[^>]*)?>([\s\S]*?)<\/style>/g;
  return [...html.matchAll(pattern)].map((match) => createHash('sha256')
    .update(match[1], 'utf8')
    .digest('base64'));
}

function updateSecurityHeaders() {
  const standalone = readFileSync(rootPath('aeropad-standalone.html'), 'utf8');
  const scriptHashes = inlineHashes(standalone, 'script');
  const styleHashes = inlineHashes(standalone, 'style');
  if (!scriptHashes.length || !styleHashes.length) {
    throw new Error('standalone output is missing inline assets for CSP hashing');
  }
  const csp = [
    "default-src 'self'",
    `script-src 'self' ${scriptHashes.map((hash) => `'sha256-${hash}'`).join(' ')}`,
    `style-src 'self' ${styleHashes.map((hash) => `'sha256-${hash}'`).join(' ')}`,
    "font-src 'self' data:",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');

  const headersPath = rootPath('_headers');
  const headers = readFileSync(headersPath, 'utf8');
  if (!/^  Content-Security-Policy: .*$/m.test(headers)) {
    throw new Error('_headers CSP line not found');
  }
  const updatedHeaders = headers.replace(
    /^  Content-Security-Policy: .*$/m,
    `  Content-Security-Policy: ${csp}`,
  );
  if (updatedHeaders !== headers) writeFileSync(headersPath, updatedHeaders);

  const vercelPath = rootPath('vercel.json');
  const vercel = readFileSync(vercelPath, 'utf8');
  if (!/("key": "Content-Security-Policy", "value": ")[^"]*(")/.test(vercel)) {
    throw new Error('vercel.json CSP value not found');
  }
  const updatedVercel = vercel.replace(
    /("key": "Content-Security-Policy", "value": ")[^"]*(")/,
    `$1${csp}$2`,
  );
  if (updatedVercel !== vercel) writeFileSync(vercelPath, updatedVercel);
}

async function buildApp() {
  assertCanonicalInputs();
  assertSelfHostedRuntimeInputs();
  await build({
    bundle: true,
    charset: 'utf8',
    entryPoints: [rootPath('src/app.js')],
    format: 'esm',
    legalComments: 'none',
    logLevel: 'warning',
    outfile: rootPath('app.js'),
    platform: 'browser',
    sourcemap: false,
    target: ['es2020'],
  });

  const app = readFileSync(rootPath('app.js'), 'utf8');
  if (!app || app.includes('</script')) {
    throw new Error('generated app.js is empty or unsafe to inline');
  }
}

function buildStandalone() {
  const result = spawnSync(process.execPath, ['scripts/build-standalone.mjs'], {
    cwd: root,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (result.status !== 0) {
    throw new Error(`standalone build failed with exit code ${result.status}`);
  }
  inlineStandaloneAssets();
  updateSecurityHeaders();
}

function copyArtifacts(destination) {
  const outputDir = rootPath(destination);
  mkdirSync(outputDir, { recursive: true });
  for (const file of generatedFiles) {
    const source = rootPath(file);
    if (!existsSync(source) || !statSync(source).isFile()) {
      throw new Error(`missing generated artifact: ${file}`);
    }
    const target = resolve(outputDir, file);
    rmSync(target, { force: true });
    cpSync(source, target);
  }
  const vendorTarget = resolve(outputDir, 'vendor');
  rmSync(vendorTarget, { force: true, recursive: true });
  cpSync(rootPath('vendor'), vendorTarget, { recursive: true });
}

function printArtifactHashes() {
  for (const file of generatedFiles) {
    const digest = createHash('sha256')
      .update(readFileSync(rootPath(file)))
      .digest('hex');
    console.log(`${file}: ${digest}`);
  }
}

if (!['full', '--app-only', '--sync-public'].includes(mode)) {
  throw new Error(`unknown build mode: ${mode}`);
}

await buildApp();
if (mode === '--app-only') {
  console.log('app.js generated from src/app.js');
} else {
  buildStandalone();
  if (mode === '--sync-public') {
    copyArtifacts('public');
  } else {
    copyArtifacts('dist');
    copyArtifacts('public');
  }
  printArtifactHashes();
}
