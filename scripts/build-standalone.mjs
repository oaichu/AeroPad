/**
 * Generates aeropad-standalone.html by inlining styles.css + app.js into index.html.
 * Single source of truth: edit index.html / styles.css / app.js, then run this script.
 * Also prints the sha256 hash of the inlined script for the CSP header (vercel.json / _headers).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const index = readFileSync('index.html', 'utf8');
const css = readFileSync('styles.css', 'utf8');
const js = readFileSync('app.js', 'utf8');

if (js.includes('</script')) {
  throw new Error('app.js contains "</script" — cannot inline safely');
}

let out = index.replace(
  '<link rel="stylesheet" href="styles.css">',
  '<style>\n' + css + '\n  </style>'
);
if (out === index) {
  throw new Error('styles.css link not found in index.html');
}

const prevOut = out;
const inlineScript = '\n' + js + '\n  ';
out = out.replace(
  '<script src="app.js"></script>',
  '<script>' + inlineScript + '</script>'
);
if (out === prevOut) {
  throw new Error('app.js script tag not found in index.html');
}

writeFileSync('aeropad-standalone.html', out);

// CSP hash-source covers the exact bytes between the script tags, whitespace included
const scriptHash = createHash('sha256').update(inlineScript, 'utf8').digest('base64');
console.log(`aeropad-standalone.html generated (${out.length} bytes)`);
console.log(`CSP inline-script sha256: ${scriptHash}`);
