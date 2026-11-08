#!/usr/bin/env node
/**
 * Single-sources the release version: reads [workspace.package] version
 * from Cargo.toml and rewrites the current-release strings + Windows
 * download URLs in apps/ui and apps/landing. Linux/macOS asset links
 * intentionally keep pointing at the last release that published them
 * (and are labeled with that version) — this script never touches a
 * version string that labels a non-Windows asset.
 *
 * Usage: node scripts/sync-version.mjs [--check]
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const cargo = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
const version = cargo.match(/\[workspace\.package\][\s\S]*?version = "([^"]+)"/)[1];
const checkOnly = process.argv.includes('--check');

function currentReleaseFiles() {
  return [
    // [file, replace-all patterns that mean "current release"]
    ['apps/ui/index.html', [/1\.0\.\d+/g]],
  ];
}

let dirty = [];
function apply(file, transforms) {
  const p = path.join(root, file);
  const before = fs.readFileSync(p, 'utf8');
  let after = before;
  for (const fn of transforms) after = fn(after);
  if (after !== before) {
    dirty.push(file);
    if (!checkOnly) fs.writeFileSync(p, after);
  }
}

// apps/ui: every 1.0.x string there is a current-release string except
// the Linux/macOS asset cards, which are labeled v1.0.28 on purpose.
apply('apps/ui/index.html', [
  (t) => t.replace(/releases\/download\/v1\.0\.\d+\/(cv\.exe|ciphervault\.exe|ciphervault-v1\.0\.\d+-x86_64-pc-windows-msvc\.zip|ciphervault-dev-v1\.0\.\d+-x86_64-pc-windows-msvc\.zip|ciphervault-node-v1\.0\.\d+-x86_64-pc-windows-msvc\.zip)/g,
    (m, asset) => `releases/download/v${version}/${asset.replace(/v1\.0\.\d+/, `v${version}`)}`),
  (t) => t.replace(/releases\/tag\/v1\.0\.\d+/g, `releases/tag/v${version}`),
  (t) => t.replace(/(CLI |Release |Download CLI |upgrade to |download the )v1\.0\.\d+/g, (m, pre) => `${pre}v${version}`),
  (t) => t.replace(/\(v1\.0\.\d+\)/g, (m, idx, s) =>
    s.slice(Math.max(0, idx - 200), idx).includes('v1.0.28') ? m : `(v${version})`),
]);

// README badge
apply('README.md', [
  (t) => t.replace(/Version-v1\.0\.\d+/, `Version-v${version}`),
]);

if (checkOnly && dirty.length) {
  console.error(`version drift (Cargo.toml=${version}): ${dirty.join(', ')}`);
  process.exit(1);
}
console.log(`version ${version} synced${checkOnly ? ' (check)' : ''}: ${dirty.length ? dirty.join(', ') : 'already in sync'}`);
