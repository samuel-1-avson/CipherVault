const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const landingDir = path.join(rootDir, 'apps', 'landing');

const htmlPath = path.join(landingDir, 'index.html');
const jsPath = path.join(landingDir, 'script.js');
const cssPath = path.join(landingDir, 'styles.css');
const cnamePath = path.join(landingDir, 'CNAME');

if (!fs.existsSync(htmlPath) || !fs.existsSync(jsPath) || !fs.existsSync(cssPath)) {
  console.error('[FAIL] Missing landing page core assets in apps/landing.');
  process.exit(1);
}

const html = fs.readFileSync(htmlPath, 'utf8');
const js = fs.readFileSync(jsPath, 'utf8');
const css = fs.readFileSync(cssPath, 'styles.css' in fs ? 'utf8' : 'utf8');
const cname = fs.existsSync(cnamePath) ? fs.readFileSync(cnamePath, 'utf8').trim() : '';

if (cname !== 'cipherv.online') {
  console.error(`[FAIL] CNAME is '${cname}', expected 'cipherv.online'.`);
  process.exit(1);
}
console.log(`[PASS] CNAME verified: '${cname}'`);

const idMatches = Array.from(js.matchAll(/getElementById\(['"]([^'"]+)['"]\)/g)).map(m => m[1]);
const uniqueIds = [...new Set(idMatches)];

let missing = 0;
for (const id of uniqueIds) {
  if (!html.includes(`id="${id}"`) && !html.includes(`id='${id}'`)) {
    console.error(`[ERROR] Missing ID in HTML: ${id}`);
    missing++;
  }
}

if (missing === 0) {
  console.log(`[PASS] All ${uniqueIds.length} element IDs referenced in script.js exist in index.html!`);
} else {
  console.error(`[FAIL] ${missing} IDs missing.`);
  process.exit(1);
}

// Check key styles
const keyClasses = [
  'theme-pill-btn', 'tui-tab-btn', 'step-pill', 'chunk-cell',
  'tui-guardian-check', 'shamir-guardian-box', 'snippet-tab', 'cmd-pill',
  'gauge-bar-fill', 'crt-scanlines', 'term-out-line', 'hero-kicker-strip',
  'tui-pillars-grid', 'pillar-card'
];

for (const cls of keyClasses) {
  if (!css.includes(`.${cls}`)) {
    console.error(`[ERROR] Missing CSS class in styles.css: .${cls}`);
    process.exit(1);
  }
}

console.log('[PASS] Core CSS classes verified in styles.css!');
