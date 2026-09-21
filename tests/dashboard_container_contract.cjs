const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');

const entrypoint = read('deploy', 'docker', 'entrypoint-dashboard.sh');
const publisherEntrypoint = read(
  'deploy',
  'docker',
  'entrypoint-public-feed-publisher.sh',
);
const accountDockerfile = read('deploy', 'docker', 'Dockerfile.account');
const accountService = read('services', 'account', 'src', 'lib.rs');
const uiApp = read('apps', 'ui', 'app.js');
const uiIndex = read('apps', 'ui', 'index.html');
assert.match(
  accountDockerfile,
  /cargo build --release(?: --locked)? --bin ciphervault-account/,
  'the account image must build the durable control-plane binary',
);
assert.match(accountService, /post_webauthn_authentication_options/);
assert.match(accountService, /post_invitation/);
assert.match(accountService, /post_recovery_codes/);
assert.match(uiApp, /navigator\.credentials\.get/);
assert.match(uiApp, /navigator\.credentials\.create/);
assert.match(uiIndex, /btn-account-manage/);
assert.match(
  accountDockerfile,
  /USER ciphervault/,
  'the account image must run as the unprivileged service user',
);
assert.match(
  entrypoint,
  /^exec ciphervault ui --serve --host 0\.0\.0\.0 --port 8080 --no-browser$/m,
  'the dashboard image must explicitly enter public serving mode',
);

// The hosted image is an explorer. It must never manufacture a shared vault or
// silently perform state-changing backup actions during startup.
assert.doesNotMatch(
  entrypoint,
  /(^|\s)ciphervault\s+(?:init|track|push|anchor)(?:\s|$)/m,
  'the public explorer entrypoint must not bootstrap a vault',
);

assert.match(
  publisherEntrypoint,
  /ciphervault publish-public-feed --output/,
  'the optional publisher worker must use the signed feed CLI command',
);
assert.match(
  publisherEntrypoint,
  /CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX/,
  'the publisher must require its dedicated signing secret',
);
assert.doesNotMatch(
  publisherEntrypoint,
  /echo\s+.*SIGNING_KEY|print.*SIGNING_KEY/i,
  'the publisher must not print the signing secret',
);
assert.doesNotMatch(
  entrypoint,
  /(^|\/)secrets(?:\/|$)/m,
  'the public explorer entrypoint must not create secret demo files',
);

// `/api/vault` is the intentionally sanitized public readiness contract. Each
// compose target must probe it without depending on private inventory.
for (const composePath of [
  ['docker-compose.yml'],
  ['deploy', 'docker-compose.prod.yml'],
  ['deploy', 'gcp', 'docker-compose.web.yml'],
]) {
  const compose = read(...composePath);
  assert.match(
    compose,
    /http:\/\/localhost:8080\/api\/vault/,
    `${composePath.join('/')} must use the public explorer readiness endpoint`,
  );
  assert.match(
    compose,
    /public-feed-publisher:/,
    `${composePath.join('/')} must define the opt-in signed feed publisher`,
  );
  assert.match(
    compose,
    /profiles:\s*\["public-feed"\]/,
    `${composePath.join('/')} must keep the publisher disabled by default`,
  );
  assert.match(
    compose,
    /CIPHERVAULT_PUBLIC_OPERATOR_TELEMETRY_FILE=/,
    `${composePath.join('/')} must provide a persistent operator observation path`,
  );
  assert.match(
    compose,
    /CIPHERVAULT_OPERATOR_REGIONS=/,
    `${composePath.join('/')} must expose regional collector configuration`,
  );
  assert.match(
    compose,
    /account:/,
    `${composePath.join('/')} must define the durable account service`,
  );
  assert.match(
    compose,
    /CIPHERVAULT_WEBAUTHN_RP_ID=/,
    `${composePath.join('/')} must configure the WebAuthn RP ID`,
  );
  assert.match(
    compose,
    /CIPHERVAULT_WEBAUTHN_ORIGIN=/,
    `${composePath.join('/')} must configure the WebAuthn origin`,
  );
  assert.match(
    compose,
    /CIPHERVAULT_ACCOUNT_COOKIE_SECURE=/,
    `${composePath.join('/')} must configure secure account cookies`,
  );
  if (composePath.includes('gcp')) {
    assert.match(
      compose,
      /CIPHERVAULT_ACCOUNT_IMAGE:\?CIPHERVAULT_ACCOUNT_IMAGE must be a signed GHCR digest/,
      `${composePath.join('/')} must require an immutable account image digest`,
    );
    assert.match(
      compose,
      /CIPHERVAULT_DASHBOARD_IMAGE:\?CIPHERVAULT_DASHBOARD_IMAGE must be a signed GHCR digest/,
      `${composePath.join('/')} must require an immutable dashboard image digest`,
    );
  } else {
    assert.match(
      compose,
      /Dockerfile\.account/,
      `${composePath.join('/')} must build the account service from its pinned Dockerfile`,
    );
  }
}

const clusterChecks = [
  read('scripts', 'verify-cluster.sh'),
  read('scripts', 'verify-cluster.ps1'),
].join('\n');
assert.doesNotMatch(
  clusterChecks,
  /\/api\/token/,
  'public-cluster verification must not require the private token route',
);
assert.doesNotMatch(
  clusterChecks,
  /tracked_files/i,
  'public-cluster verification must not treat readiness as private vault inventory',
);
assert.doesNotMatch(
  clusterChecks,
  /\/api\/fleet/,
  'public-cluster verification must not treat the private maintenance fleet as public readiness data',
);
assert.match(
  clusterChecks,
  /\/api\/operators/,
  'public-cluster verification must probe the explicitly public operator telemetry endpoint',
);

console.log('Dashboard container deployment contract checks passed.');

// F1: the explorer object endpoint fans out to every operator per request,
// so the public edge must bound it per client before traffic reaches the app.
const webCaddyfile = read('deploy', 'gcp', 'Caddyfile.web.gcp');
assert.match(
  webCaddyfile,
  /handle \/api\/explorer\/object\/\*/,
  'the public edge must give the explorer object API its own rate-limited route',
);
assert.match(
  webCaddyfile,
  /zone explorer_object[\s\S]*events 30[\s\S]*window 1m/,
  'the explorer object zone must stay at its reviewed budget',
);
assert.match(
  webCaddyfile,
  /zone explorer_general/,
  'the public edge must rate-limit general explorer traffic',
);
