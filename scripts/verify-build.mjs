import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const generatedFiles = ['index.html', 'styles.css', 'app.js', 'aeropad-standalone.html', '_headers'];
const requiredDevDependencies = { esbuild: '0.28.2', jsdom: '26.1.0', jsqr: '1.4.0', 'qrcode-generator': '2.0.4' };
const forbiddenRuntimeReferences = ['cdn.jsdelivr.net', 'fonts.googleapis.com', 'fonts.gstatic.com', 'rsms.me', 'unsafe-inline'];

const rootPath = relativePath => resolve(root, relativePath);
const fail = message => { throw new Error(message); };
const assert = (condition, message) => { if (!condition) fail(message); };
const readJson = relativePath => JSON.parse(readFileSync(rootPath(relativePath), 'utf8'));
const sha256 = filePath => createHash('sha256').update(readFileSync(filePath)).digest('hex');

function listFiles(relativeDirectory) {
  const directory = rootPath(relativeDirectory);
  assert(existsSync(directory) && statSync(directory).isDirectory(), `missing directory: ${relativeDirectory}`);
  const files = [];
  const visit = (current, prefix = '') => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const relative = join(prefix, entry.name);
      const absolute = join(current, entry.name);
      if (entry.isDirectory()) visit(absolute, relative);
      else if (entry.isFile()) files.push(relative);
      else fail(`unsupported vendor entry: ${relative}`);
    }
  };
  visit(directory);
  return files.sort();
}

function assertDependencies() {
  const pkg = readJson('package.json');
  assert(pkg.scripts?.verify === 'node scripts/verify-build.mjs', 'package.json must wire npm run verify');
  const lock = readJson('package-lock.json');
  assert(lock.lockfileVersion === 3, 'package-lock.json must use lockfileVersion 3');
  const lockRoot = lock.packages?.[''];
  assert(lockRoot, 'package-lock.json is missing the root package entry');
  for (const [name, version] of Object.entries(requiredDevDependencies)) {
    assert(pkg.devDependencies?.[name] === version, `package.json missing pinned devDependency ${name}@${version}`);
    assert(lockRoot.devDependencies?.[name] === version, `package-lock root missing ${name}@${version}`);
    assert(lock.packages?.[`node_modules/${name}`]?.version === version, `lockfile does not resolve ${name}@${version}`);
  }
  console.log('[verify] dependency declarations and lockfile: PASS');
}

function assertRuntimeInputs() {
  const input = ['index.html', '_headers', 'vercel.json'].map(file => readFileSync(rootPath(file), 'utf8')).join('\n');
  for (const reference of forbiddenRuntimeReferences) assert(!input.includes(reference), `forbidden runtime reference: ${reference}`);
  const policy = readFileSync(rootPath('_headers'), 'utf8');
  assert(policy.includes("script-src 'self'") && policy.includes("style-src 'self'"), 'CSP must keep self-only script/style sources');
  console.log('[verify] self-hosted runtime and CSP inputs: PASS');
}

function assertArtifactParity() {
  const outputs = ['public', 'dist'];
  for (const file of generatedFiles) {
    const paths = [file, ...outputs.map(directory => `${directory}/${file}`)];
    const hashes = paths.map(relativePath => {
      assert(existsSync(rootPath(relativePath)), `missing generated artifact: ${relativePath}`);
      return sha256(rootPath(relativePath));
    });
    assert(new Set(hashes).size === 1, `generated artifact drift: ${file}`);
  }
  const vendorFiles = listFiles('vendor');
  for (const directory of outputs) {
    const copiedFiles = listFiles(`${directory}/vendor`);
    assert(JSON.stringify(copiedFiles) === JSON.stringify(vendorFiles), `vendor file drift: ${directory}`);
    for (const file of vendorFiles) assert(sha256(rootPath(`vendor/${file}`)) === sha256(rootPath(`${directory}/vendor/${file}`)), `vendor hash drift: ${directory}/${file}`);
  }
  console.log(`[verify] generated artifacts and vendor hashes: PASS (${generatedFiles.length} artifacts)`);
}

function assertStandaloneCsp() {
  const html = readFileSync(rootPath('aeropad-standalone.html'), 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  const styles = [...html.matchAll(/<style(?:\s[^>]*)?>([\s\S]*?)<\/style>/g)];
  assert(scripts.length === 1 && styles.length === 2, 'standalone must contain one script and two styles');
  assert(!/<script\s+src=/i.test(html) && !/<link[^>]+rel=["']stylesheet/i.test(html), 'standalone must be self-contained');
  const digest = contents => createHash('sha256').update(contents, 'utf8').digest('base64');
  const scriptTokens = scripts.map(match => `'sha256-${digest(match[1])}'`).join(' ');
  const styleTokens = styles.map(match => `'sha256-${digest(match[1])}'`).join(' ');
  const headerCsp = readFileSync(rootPath('_headers'), 'utf8').match(/^\s*Content-Security-Policy:\s*(.+)$/m)?.[1];
  const vercel = readJson('vercel.json');
  const vercelCsp = vercel.headers?.flatMap(rule => rule.headers ?? []).find(header => header.key === 'Content-Security-Policy')?.value;
  assert(headerCsp && vercelCsp && headerCsp === vercelCsp, 'deployment CSP policies must match');
  assert(headerCsp.includes(`script-src 'self' ${scriptTokens}`), 'standalone script CSP hash is stale');
  assert(headerCsp.includes(`style-src 'self' ${styleTokens}`), 'standalone style CSP hash is stale');
  const metaCsp = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/)?.[1];
  assert(metaCsp, 'standalone must embed a CSP <meta> for headerless contexts (file://, local HTTP)');
  assert(`${metaCsp}; frame-ancestors 'none'` === headerCsp, 'standalone meta CSP must mirror the header policy');
  console.log('[verify] standalone CSP hashes: PASS');
}

function run(command, args) {
  console.log(`[verify] ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  assert(result.status === 0, `${command} ${args.join(' ')} exited with ${result.status}`);
}

function snapshot(destination) {
  mkdirSync(destination, { recursive: true });
  for (const file of generatedFiles) cpSync(rootPath(file), join(destination, file));
  cpSync(rootPath('vendor'), join(destination, 'vendor'), { recursive: true });
}

function assertDeterministicBuild() {
  const temporaryDirectory = mkdtempSync(join(rootPath('node_modules'), '.aeropad-verify-'));
  try {
    const first = join(temporaryDirectory, 'first');
    const second = join(temporaryDirectory, 'second');
    snapshot(first);
    run(npm, ['run', 'build']);
    snapshot(second);
    const result = spawnSync('git', ['diff', '--no-index', '--exit-code', '--', first, second], { cwd: root, stdio: 'inherit' });
    if (result.error) throw result.error;
    assert(result.status === 0, `git diff --exit-code found nondeterministic output (${result.status})`);
    console.log('[verify] deterministic generated outputs via git diff --exit-code: PASS');
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function verify() {
  assertDependencies();
  assertRuntimeInputs();
  run(npm, ['test']);
  run(npm, ['run', 'e2e']);
  run(npm, ['run', 'build']);
  assertArtifactParity();
  assertStandaloneCsp();
  assertDeterministicBuild();
  assertArtifactParity();
  assertStandaloneCsp();
  console.log('[verify] full verification: PASS');
}

try { verify(); } catch (error) {
  console.error(`[verify] FAILED: ${error.message}`);
  process.exitCode = 1;
}
