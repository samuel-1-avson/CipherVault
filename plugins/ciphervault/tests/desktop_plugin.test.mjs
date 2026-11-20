/**
 * Automated Node render & interaction tests for the CipherVault Hermes Desktop plugin.
 *
 * Zero external dependencies: uses Node's built-in test runner (`node --test`) and
 * `node:module` loader hooks to mock `@hermes/plugin-sdk`, `react`, and
 * `react/jsx-runtime`, then recursively renders every registered React function
 * component with its actual `props` object (catching React prop-destructuring bugs
 * like `function VaultPane(ctx)` vs `function VaultPane({ ctx })`).
 */
import assert from 'node:assert/strict'
import fs from 'node:fs'
import module from 'node:module'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PLUGIN_PATH = path.resolve(__dirname, '..', 'desktop', 'plugin.js')

// Shared mock bridge accessed by the virtual ESM modules in the main thread.
const mockState = {
  cwd: '/workspace/demo-repo',
  i18n: {},
  haptics: [],
  navigations: [],
  notifications: [],
  clipboardCalls: [],
  clipboardMode: 'promise', // 'promise' | 'reject' | 'unavailable'
  useStateImpl: null,
  useQueryImpl: null
}

globalThis.__CV_DESKTOP_TEST_MOCKS__ = {
  cn: (...parts) => parts.filter(Boolean).join(' '),
  haptic: (kind) => { mockState.haptics.push(kind) },
  host: {
    state: {
      get cwd() {
        return { __signal: 'cwd', get: () => mockState.cwd }
      }
    },
    navigate: (route) => { mockState.navigations.push(route) },
    notify: (evt) => { mockState.notifications.push(evt) },
    clipboard: {
      writeText: (text) => {
        mockState.clipboardCalls.push(text)
        if (mockState.clipboardMode === 'unavailable') return null
        if (mockState.clipboardMode === 'reject') return Promise.reject(new Error('denied'))
        return Promise.resolve()
      }
    }
  },
  Tip: ({ label, children }) => ({
    $$el: true,
    type: 'mock-tip',
    props: { label, children },
    key: undefined
  }),
  usePluginI18n: (id) => (key, ...args) => {
    const table = mockState.i18n[id]?.en || {}
    const entry = table[key]
    if (typeof entry === 'function') return entry(...args)
    if (typeof entry === 'string') return entry
    return key
  },
  useValue: (sig) => (sig && typeof sig.get === 'function' ? sig.get() : sig),
  useQuery: (opts) => mockState.useQueryImpl(opts),
  useState: (initial) => mockState.useStateImpl(initial),
  jsx: (type, props, key) => ({ $$el: true, type, props: props || {}, key }),
  jsxs: (type, props, key) => ({ $$el: true, type, props: props || {}, key }),
  PALETTE_AREA: 'palette',
  ROUTES_AREA: 'routes'
}

const LOADER_SOURCE = `
export async function resolve(specifier, context, nextResolve) {
  if (
    specifier === '@hermes/plugin-sdk' ||
    specifier === 'react' ||
    specifier === 'react/jsx-runtime'
  ) {
    return { url: 'cv-mock:///' + encodeURIComponent(specifier), shortCircuit: true }
  }
  return nextResolve(specifier, context)
}

export async function load(url, context, nextLoad) {
  if (url === 'cv-mock:///' + encodeURIComponent('@hermes/plugin-sdk')) {
    return {
      format: 'module',
      shortCircuit: true,
      source: \`
        const m = globalThis.__CV_DESKTOP_TEST_MOCKS__;
        export const cn = (...a) => m.cn(...a);
        export const haptic = (...a) => m.haptic(...a);
        export const host = m.host;
        export const Tip = (props) => m.Tip(props);
        export const usePluginI18n = (...a) => m.usePluginI18n(...a);
        export const useQuery = (...a) => m.useQuery(...a);
        export const useValue = (...a) => m.useValue(...a);
        export const PALETTE_AREA = m.PALETTE_AREA;
        export const ROUTES_AREA = m.ROUTES_AREA;
      \`
    }
  }
  if (url === 'cv-mock:///' + encodeURIComponent('react')) {
    return {
      format: 'module',
      shortCircuit: true,
      source: \`
        const m = globalThis.__CV_DESKTOP_TEST_MOCKS__;
        export const useState = (...a) => m.useState(...a);
      \`
    }
  }
  if (url === 'cv-mock:///' + encodeURIComponent('react/jsx-runtime')) {
    return {
      format: 'module',
      shortCircuit: true,
      source: \`
        const m = globalThis.__CV_DESKTOP_TEST_MOCKS__;
        export const jsx = (...a) => m.jsx(...a);
        export const jsxs = (...a) => m.jsxs(...a);
      \`
    }
  }
  return nextLoad(url, context)
}
`

module.register('data:text/javascript,' + encodeURIComponent(LOADER_SOURCE))

const { default: plugin } = await import(pathToFileURL(PLUGIN_PATH).href)

/**
 * Lightweight deterministic React renderer + query cache.
 *
 * Crucially, every function component is invoked strictly as `Component(el.props)`
 * — matching React's real calling convention so missing `{ ctx }` destructuring
 * throws `TypeError: ctx.rest is not a function`.
 */
function createHarness({ cwd = '/workspace/demo-repo', handlers = {} } = {}) {
  mockState.cwd = cwd
  mockState.i18n = {}
  mockState.haptics = []
  mockState.navigations = []
  mockState.notifications = []
  mockState.clipboardCalls = []
  mockState.clipboardMode = 'promise'

  const restCalls = []
  const queryErrors = []
  const queryCache = new Map()
  const componentStates = new Map()
  let activePath = null
  let hookCursor = 0

  mockState.useStateImpl = (initial) => {
    const key = activePath
    if (!componentStates.has(key)) componentStates.set(key, [])
    const slots = componentStates.get(key)
    const idx = hookCursor++
    if (idx >= slots.length) {
      slots.push(typeof initial === 'function' ? initial() : initial)
    }
    const setState = (next) => {
      slots[idx] = typeof next === 'function' ? next(slots[idx]) : next
    }
    return [slots[idx], setState]
  }

  const runQueryEntry = (qKey, queryFn) => {
    const entry = queryCache.get(qKey)
    const p = Promise.resolve()
      .then(() => queryFn())
      .then(
        (data) => {
          entry.data = data
          entry.isLoading = false
          entry.isError = false
          entry.error = null
          return data
        },
        (err) => {
          entry.data = undefined
          entry.isLoading = false
          entry.isError = true
          entry.error = err
          queryErrors.push({ queryKey: qKey, error: err })
          return undefined
        }
      )
    entry.pending = p
    return p
  }

  mockState.useQueryImpl = ({ queryKey, enabled = true, queryFn }) => {
    const qKey = JSON.stringify(queryKey)
    if (!queryCache.has(qKey)) {
      queryCache.set(qKey, {
        data: undefined,
        isLoading: Boolean(enabled),
        isError: false,
        error: null,
        started: false,
        pending: null,
        queryFn
      })
    }
    const entry = queryCache.get(qKey)
    entry.queryFn = queryFn
    if (enabled && !entry.started) {
      entry.started = true
      entry.isLoading = true
      runQueryEntry(qKey, queryFn)
    }
    return {
      data: entry.data,
      isLoading: enabled ? entry.isLoading : false,
      isError: entry.isError,
      error: entry.error,
      refetch: () => runQueryEntry(qKey, entry.queryFn)
    }
  }

  const registered = new Map()
  const ctx = {
    i18n: {
      register(bundles) {
        mockState.i18n[plugin.id] = bundles
      }
    },
    register(item) {
      registered.set(item.id, item)
    },
    async rest(endpoint, init) {
      assert.equal(typeof endpoint, 'string', 'ctx.rest endpoint must be a string')
      assert.ok(endpoint.startsWith('/'), `ctx.rest endpoint must start with '/': ${endpoint}`)
      const method = (init && init.method) || 'GET'
      const body = init && init.body ? JSON.parse(init.body) : undefined
      restCalls.push({ endpoint, method, body, headers: init?.headers })
      const route = endpoint.split('?')[0]
      const handler = handlers[`${method} ${route}`] || handlers[route]
      if (!handler) {
        throw new Error(`No mock REST handler for ${method} ${endpoint}`)
      }
      return handler({ endpoint, method, body, init })
    }
  }

  plugin.register(ctx)

  const renderNode = (node, treePath) => {
    if (node == null || typeof node === 'boolean' || typeof node === 'string' || typeof node === 'number') {
      return node
    }
    if (Array.isArray(node)) {
      return node.map((child, idx) => renderNode(child, `${treePath}[${idx}]`))
    }
    if (node && node.$$el) {
      if (typeof node.type === 'function') {
        const compName = node.type.name || 'Anonymous'
        const nextPath = `${treePath}>${compName}${node.key != null ? '#' + node.key : ''}`
        const prevPath = activePath
        const prevCursor = hookCursor
        activePath = nextPath
        hookCursor = 0
        let rendered
        try {
          // Strict React call: always pass the props object as arg 0!
          rendered = node.type(node.props)
        } finally {
          activePath = prevPath
          hookCursor = prevCursor
        }
        return renderNode(rendered, nextPath)
      }
      const children = node.props && 'children' in node.props
        ? renderNode(node.props.children, `${treePath}/${String(node.type)}`)
        : undefined
      return {
        type: node.type,
        key: node.key,
        props: { ...node.props, children }
      }
    }
    return node
  }

  const settleQueries = async () => {
    for (let i = 0; i < 6; i++) {
      const pending = [...queryCache.values()].map(e => e.pending).filter(Boolean)
      if (!pending.length) break
      await Promise.all(pending)
      for (const e of queryCache.values()) e.pending = null
    }
  }

  const renderSurface = async (surfaceId) => {
    const item = registered.get(surfaceId)
    assert.ok(item, `surface '${surfaceId}' must be registered`)
    // First pass triggers initial queries; settle & re-render so enabled
    // dependent queries (audit, pending-prompts, env-health) also fire and resolve.
    let tree = renderNode(item.render(), surfaceId)
    await settleQueries()
    tree = renderNode(item.render(), surfaceId)
    await settleQueries()
    tree = renderNode(item.render(), surfaceId)
    return tree
  }

  const rerenderSurface = (surfaceId) => {
    const item = registered.get(surfaceId)
    return renderNode(item.render(), surfaceId)
  }

  return {
    ctx,
    registered,
    restCalls,
    queryErrors,
    renderSurface,
    rerenderSurface,
    settleQueries
  }
}

function collectText(node, out = []) {
  if (node == null || typeof node === 'boolean') return out
  if (typeof node === 'string' || typeof node === 'number') {
    out.push(String(node))
    return out
  }
  if (Array.isArray(node)) {
    for (const child of node) collectText(child, out)
    return out
  }
  if (node.props && 'children' in node.props) {
    collectText(node.props.children, out)
  }
  return out
}

function findAll(node, predicate, out = []) {
  if (node == null || typeof node !== 'object') return out
  if (Array.isArray(node)) {
    for (const child of node) findAll(child, predicate, out)
    return out
  }
  if (predicate(node)) out.push(node)
  if (node.props && 'children' in node.props) {
    findAll(node.props.children, predicate, out)
  }
  return out
}

function findButton(tree, label) {
  return findAll(tree, n => n.type === 'button' && collectText(n).join('').trim() === label)[0]
}

function assertNoDuplicateSiblingKeys(node) {
  if (node == null || typeof node !== 'object') return
  if (Array.isArray(node)) {
    const seen = new Set()
    for (const child of node) {
      if (child && typeof child === 'object' && child.key != null) {
        const k = String(child.key)
        assert.ok(!seen.has(k), `duplicate React sibling key detected: ${k}`)
        seen.add(k)
      }
      assertNoDuplicateSiblingKeys(child)
    }
    return
  }
  if (node.props && 'children' in node.props) {
    assertNoDuplicateSiblingKeys(node.props.children)
  }
}

function defaultHandlers(overrides = {}) {
  return {
    'GET /status': () => ({
      binary: 'ok',
      vault: true,
      vault_id_short: 'v1234abcd',
      active_head_short: 'h9876fedc',
      working_tree_sealed: true,
      working_tree_plaintext_files: [],
      tracked_files: 2,
      tracked_paths: ['.env', '.env.local'],
      operators: 3,
      current_epoch: 2,
      cli_version: '1.0.35',
      policy_profiles: [
        {
          name: 'test',
          description: 'Offline unit test profile',
          commands: ['pytest', 'cargo test'],
          allow_keys: ['DATABASE_URL', 'TEST_*'],
          allow_keys_count: 2,
          require_keys: ['DATABASE_URL'],
          no_net: true,
          proxy: false,
          upstreams: []
        },
        {
          name: 'llm_eval',
          description: 'Proxied LLM eval keys',
          commands: ['python'],
          allow_keys: ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY'],
          allow_keys_count: 2,
          require_keys: [],
          no_net: false,
          proxy: true,
          upstreams: ['CUSTOM_GATEWAY=https://gateway.example.com']
        }
      ]
    }),
    'GET /audit': () => ({
      success: true,
      binary: 'ok',
      verification: { ok: true },
      entries: [
        { id: 0, tool: 'ciphervault_run', decision: 'scrubbed_result', path: '.env' },
        { entry_hash: 'deadbeef', tool: 'terminal', decision: 'blocked', path: '.env' },
        { timestamp: '2026-11-18T00:00:00Z', tool: 'read_file', decision: 'blocked', path: '.env.local' }
      ]
    }),
    'GET /pending-prompts': () => ({
      success: true,
      keys: [],
      env_file: '.env',
      seal: true
    }),
    'GET /env-health': () => ({
      success: true,
      vault_keys: ['DATABASE_URL'],
      referenced_in_code: ['DATABASE_URL', 'STRIPE_SECRET_KEY', 'JWT_SECRET'],
      example_keys: ['DATABASE_URL', 'JWT_SECRET'],
      missing_in_vault: ['STRIPE_SECRET_KEY', 'JWT_SECRET'],
      unreferenced_in_code: [],
      value_anomalies: [{ key: 'LEGACY_TOKEN', file: '.env', issue: 'EMPTY_VALUE' }]
    }),
    'POST /seal': () => ({ binary: 'ok', vault: true, working_tree_sealed: true }),
    'POST /set': ({ body }) => ({
      success: true,
      key: body.key,
      env_file: body.env_file,
      sealed: body.seal,
      snapshot_head: 'a1b2c3d4'
    }),
    'POST /generate': ({ body }) => ({
      success: true,
      name: body.name,
      format: body.format || 'base64url',
      length_chars: 43,
      sha256_prefix: '9f8e7d6c',
      env_file: body.env_file || '.env',
      sealed: body.seal !== false,
      snapshot_head: 'e5f60718'
    }),
    ...overrides
  }
}

test('desktop plugin imports only allowed Hermes Desktop modules and avoids Math.random keys', () => {
  const src = fs.readFileSync(PLUGIN_PATH, 'utf8')
  const imports = [...src.matchAll(/^\s*import\s+[\s\S]*?\s+from\s+['"]([^'"]+)['"]/gm)].map(m => m[1])
  assert.deepEqual(imports.sort(), ['@hermes/plugin-sdk', 'react', 'react/jsx-runtime'])
  assert.doesNotMatch(src, /Math\.random\s*\(/, 'plugin.js must not use Math.random() for React keys')
})

test('all registered surfaces independently destructure { ctx } and invoke status/audit/pending-prompts/env-health via ctx.rest', async () => {
  const cwd = '/tmp/my vault'
  const enc = encodeURIComponent(cwd)

  // Verify each surface on a fresh harness so queryCache never masks a missing { ctx }
  // destructuring in VaultPane, VaultPage, VaultChip, or StatusBody.
  const hPane = createHarness({ cwd, handlers: defaultHandlers() })
  assert.equal(plugin.id, 'ciphervault')
  assert.deepEqual([...hPane.registered.keys()].sort(), ['chip', 'explorer', 'explorer-open', 'open', 'page', 'pane'])
  assert.equal(hPane.registered.get('open').render(), null)

  const paneTree = await hPane.renderSurface('pane')
  assert.deepEqual(hPane.queryErrors, [], 'VaultPane/StatusBody must have zero queryFn errors')
  assertNoDuplicateSiblingKeys(paneTree)
  const paneText = collectText(paneTree).join('\n')
  findButton(paneTree, 'Open Network Explorer').props.onClick()
  assert.equal(mockState.navigations.at(-1), '/ciphervault/explorer')
  assert.doesNotMatch(paneText, /Vault backend unavailable/)
  assert.match(paneText, /v1234abcd/)
  assert.match(paneText, /sealed \(0B on disk\)/)
  const paneEndpoints = hPane.restCalls.map(c => `${c.method} ${c.endpoint}`)
  assert.ok(paneEndpoints.includes(`GET /status?cwd=${enc}`), `missing GET /status: ${paneEndpoints}`)
  assert.ok(paneEndpoints.includes(`GET /audit?cwd=${enc}&limit=10`), `missing GET /audit: ${paneEndpoints}`)
  assert.ok(paneEndpoints.includes(`GET /pending-prompts?cwd=${enc}`), `missing GET /pending-prompts: ${paneEndpoints}`)
  assert.ok(paneEndpoints.includes(`GET /env-health?cwd=${enc}`), `missing GET /env-health: ${paneEndpoints}`)

  // Refresh button refetches status + dependent vault queries
  const beforeRefresh = hPane.restCalls.length
  const refreshBtn = findButton(paneTree, 'Refresh')
  assert.ok(refreshBtn, 'Refresh button must render')
  refreshBtn.props.onClick()
  await hPane.settleQueries()
  assert.ok(hPane.restCalls.length >= beforeRefresh + 4, 'Refresh must refetch status, audit, pending-prompts, and env-health')

  // Fresh harness for VaultPage
  const hPage = createHarness({ cwd, handlers: defaultHandlers() })
  const pageTree = await hPage.renderSurface('page')
  assert.deepEqual(hPage.queryErrors, [], 'VaultPage/StatusBody must have zero queryFn errors')
  assertNoDuplicateSiblingKeys(pageTree)
  const pageText = collectText(pageTree).join('\n')
  assert.doesNotMatch(pageText, /Vault backend unavailable/)
  assert.match(pageText, /v1234abcd/)
  assert.ok(hPage.restCalls.some(c => c.method === 'GET' && c.endpoint === `/status?cwd=${enc}`))
  assert.ok(hPage.restCalls.some(c => c.method === 'GET' && c.endpoint === `/audit?cwd=${enc}&limit=10`))
  assert.ok(hPage.restCalls.some(c => c.method === 'GET' && c.endpoint === `/pending-prompts?cwd=${enc}`))
  assert.ok(hPage.restCalls.some(c => c.method === 'GET' && c.endpoint === `/env-health?cwd=${enc}`))

  // Fresh harness for VaultChip
  const hChip = createHarness({ cwd, handlers: defaultHandlers() })
  const chipTree = await hChip.renderSurface('chip')
  assert.deepEqual(hChip.queryErrors, [], 'VaultChip must have zero queryFn errors')
  assert.ok(hChip.restCalls.some(c => c.method === 'GET' && c.endpoint === `/status?cwd=${enc}`))
  const chipSpans = findAll(chipTree, n => n.type === 'span')
  assert.ok(chipSpans.some(s => String(s.props.className || '').includes('bg-emerald-400')))
  const chipBtn = findAll(chipTree, n => n.type === 'button')[0]
  chipBtn.props.onClick()
  hChip.registered.get('open').data.run()
  assert.deepEqual(mockState.navigations, ['/ciphervault', '/ciphervault'])
})

test('Network Explorer renders in Hermes and supports lookup and local block navigation', async () => {
  const cid = 'ab'.repeat(32)
  const block = { height: 2, hash: 'cd'.repeat(32), commitments: 1, signatures: 1, timestamp_signed: true, timestamp_ms: 1760000000000 }
  const h = createHarness({ cwd: '/workspace/vault', handlers: {
    '/explorer': () => ({ state: 'ready', counts: { reachable: 2, total: 3 }, feed: { count: 1 },
      operators_available: true, operators: [{ operator_id: 'op1', status: 'reachable', latency_ms: 42 }],
      anchors_available: true, anchors: [{ tx_hash_hex: cid, block_number: 2, finality_status: 'unverified' }] }),
    '/explorer/object': () => ({ state: 'ready', cid, quorum: { present: 2, required: 3, satisfied: false },
      replicas: [{ operator_id: 'op1', status: 'present' }] }),
    '/explorer/chain': ({ endpoint }) => ({ state: 'ready', solo: true, blocks: [block],
      detail: endpoint.endsWith('query=2') ? { block, parent_hash: cid, transaction_root: cid,
        commitments: [cid], signers: ['de'.repeat(32)] } : null }),
  } })
  assert.equal(h.registered.get('explorer').data.path, '/ciphervault/explorer')
  let tree = await h.renderSurface('explorer')
  let text = collectText(tree).join('\n')
  assert.match(text, /Network Explorer/)
  assert.match(text, /2 \/ 3 responding/)
  assert.match(text, /42 ms/)
  assert.equal(h.restCalls.length, 1)

  findAll(tree, node => node.props?.['aria-label'] === 'Object CID')[0]
    .props.onChange({ currentTarget: { value: cid } })
  tree = h.rerenderSurface('explorer')
  findAll(tree, node => node.type === 'form')[0].props.onSubmit({ preventDefault() {} })
  tree = await h.renderSurface('explorer')
  assert.match(collectText(tree).join('\n'), /Quorum shortfall/)
  assert.ok(h.restCalls.some(call => call.endpoint === '/explorer/object?cid=' + cid))

  findButton(tree, 'Local CipherChain').props.onClick()
  tree = await h.renderSurface('explorer')
  findButton(tree, 'Block #2').props.onClick()
  tree = await h.renderSurface('explorer')
  text = collectText(tree).join('\n')
  assert.match(text, /Solo ledger/)
  assert.match(text, /Transaction root/)
  assert.match(text, /Signed time/)
  assert.ok(h.restCalls.some(call => call.endpoint === '/explorer/chain?cwd=%2Fworkspace%2Fvault&query=2'))
  assert.deepEqual(h.queryErrors, [])
})

test('status card renders active policy profiles and handles policy_error cleanly', async () => {
  const h = createHarness({ handlers: defaultHandlers() })
  const tree = await h.renderSurface('pane')
  const text = collectText(tree).join('\n')

  assert.match(text, /2 active/)
  assert.match(text, /Active policy profiles/)
  assert.match(text, /\btest\b/)
  assert.match(text, /Offline unit test profile/)
  assert.match(text, /no-net/)
  assert.match(text, /\bllm_eval\b/)
  assert.match(text, /Proxied LLM eval keys/)
  assert.match(text, /proxy/)
  assert.match(text, /2 keys/)

  const hErr = createHarness({
    handlers: defaultHandlers({
      'GET /status': () => ({
        ...defaultHandlers()['GET /status'](),
        policy_profiles: [],
        policy_error: 'invalid TOML at line 4'
      })
    })
  })
  const errTree = await hErr.renderSurface('pane')
  const errText = collectText(errTree).join('\n')
  assert.match(errText, /invalid policy\.toml/)
  assert.match(errText, /Policy parse error: invalid TOML at line 4/)
})

test('audit trail and dynamic lists produce deterministic unique React keys across renders', async () => {
  const h = createHarness({ handlers: defaultHandlers() })
  const tree1 = await h.renderSurface('pane')
  const tree2 = h.rerenderSurface('pane')

  const auditKeys1 = findAll(tree1, n => typeof n.key === 'string' && n.key.startsWith('audit-')).map(n => n.key)
  const auditKeys2 = findAll(tree2, n => typeof n.key === 'string' && n.key.startsWith('audit-')).map(n => n.key)

  assert.equal(auditKeys1.length, 3)
  assert.equal(new Set(auditKeys1).size, 3, 'audit keys must be unique')
  assert.deepEqual(auditKeys1, auditKeys2, 'audit keys must be deterministic across re-renders')
  assert.equal(auditKeys1[0], 'audit-0', 'id: 0 must not be treated as falsy')
  assert.equal(auditKeys1[1], 'audit-deadbeef')
})

test('unsealed vault displays Seal button and calls POST /seal via ctx.rest', async () => {
  let sealed = false
  const h = createHarness({
    handlers: defaultHandlers({
      'GET /status': () => ({
        ...defaultHandlers()['GET /status'](),
        working_tree_sealed: sealed
      }),
      'POST /seal': () => {
        sealed = true
        return { binary: 'ok', vault: true, working_tree_sealed: true }
      }
    })
  })

  const chipBefore = await h.renderSurface('chip')
  assert.ok(findAll(chipBefore, n => n.type === 'span' && String(n.props.className || '').includes('bg-amber-400')).length > 0)

  const tree = await h.renderSurface('pane')
  const sealBtn = findButton(tree, 'Seal & shred .env')
  assert.ok(sealBtn, 'Seal button should render when working_tree_sealed is false')

  await sealBtn.props.onClick()
  await h.settleQueries()

  const sealCall = h.restCalls.find(c => c.method === 'POST' && c.endpoint.startsWith('/seal?cwd='))
  assert.ok(sealCall, 'POST /seal must be invoked via ctx.rest')
  assert.ok(mockState.notifications.some(n => n.kind === 'success' && n.message.includes('sealed')))
})

test('Env Health missing rows offer Fill (pre-populates drawer) and Generate (POST /generate + Copy ready note)', async () => {
  const h = createHarness({ handlers: defaultHandlers() })
  let tree = await h.renderSurface('pane')

  const fillButtons = findAll(tree, n => n.type === 'button' && collectText(n).join('') === 'Fill')
  const genButtons = findAll(tree, n => n.type === 'button' && collectText(n).join('') === 'Generate')
  assert.equal(fillButtons.length, 2, 'each missing key row must render a Fill button')
  assert.equal(genButtons.length, 2, 'each missing key row must render a Generate button')

  // 1. Clicking Fill on STRIPE_SECRET_KEY opens the Secret Entry Drawer pre-filled with that key
  fillButtons[0].props.onClick()
  tree = h.rerenderSurface('pane')
  const keyInput = findAll(tree, n => n.type === 'input' && n.props.type === 'text')[0]
  assert.ok(keyInput, 'Secret Entry Drawer form must expand when Fill is clicked')
  assert.equal(keyInput.props.value, 'STRIPE_SECRET_KEY')

  // 2. Clicking Generate on JWT_SECRET invokes POST /generate via ctx.rest
  const genBtn2 = findAll(tree, n => n.type === 'button' && collectText(n).join('') === 'Generate')[1]
  await genBtn2.props.onClick()
  await h.settleQueries()

  const genCall = h.restCalls.find(c => c.method === 'POST' && c.endpoint.startsWith('/generate?cwd='))
  assert.ok(genCall, 'POST /generate must be called via ctx.rest')
  assert.deepEqual(genCall.body, {
    name: 'JWT_SECRET',
    format: 'base64url',
    bytes: 32,
    env_file: '.env',
    seal: true,
    overwrite: false
  })
  assert.ok(
    mockState.notifications.some(n => n.kind === 'success' && n.message.includes('JWT_SECRET') && n.message.includes('9f8e7d6c')),
    'success toast should include key name and short sha256 prefix'
  )

  // 3. Ready-note banner appears and copies a non-secret continuation message
  tree = h.rerenderSurface('pane')
  const copyReadyBtn = findButton(tree, 'Copy ready note')
  assert.ok(copyReadyBtn, 'Copy ready note button must appear after generating a secret')
  copyReadyBtn.props.onClick()
  await Promise.resolve()
  assert.deepEqual(mockState.clipboardCalls, ['Configured JWT_SECRET in CipherVault — you can continue.'])
})

test('Secret Entry Drawer handles pending prompts, POST /set, clears secret value, and offers non-secret Copy ready note', async () => {
  const SECRET_VAL = 'sk-test-super-secret-value-never-leak'
  const h = createHarness({
    handlers: defaultHandlers({
      'GET /pending-prompts': () => ({
        success: true,
        env_file: '.env',
        seal: true,
        keys: [
          {
            name: 'OPENAI_API_KEY',
            reason: 'Needed for eval harness',
            expected_prefix: 'sk-',
            env_file: '.env.local',
            seal: true
          }
        ]
      })
    })
  })

  let tree = await h.renderSurface('pane')

  // Pending chip click populates key name & env_file
  const chip = findAll(tree, n => n.type === 'button' && collectText(n).join('').includes('OPENAI_API_KEY'))[0]
  assert.ok(chip, 'pending prompt chip should render')
  chip.props.onClick()
  tree = h.rerenderSurface('pane')

  const keyInput = findAll(tree, n => n.type === 'input' && n.props.type === 'text')[0]
  const valInput = findAll(tree, n => n.type === 'input' && n.props.type === 'password')[0]
  const selectEl = findAll(tree, n => n.type === 'select')[0]
  assert.equal(keyInput.props.value, 'OPENAI_API_KEY')
  assert.equal(selectEl.props.value, '.env.local')

  // Enter secret value & submit
  valInput.props.onChange({ target: { value: SECRET_VAL } })
  tree = h.rerenderSurface('pane')
  const form = findAll(tree, n => n.type === 'form')[0]
  await form.props.onSubmit({ preventDefault() {} })
  await h.settleQueries()

  const setCall = h.restCalls.find(c => c.method === 'POST' && c.endpoint.startsWith('/set?cwd='))
  assert.ok(setCall, 'POST /set must be called via ctx.rest')
  assert.deepEqual(setCall.body, {
    key: 'OPENAI_API_KEY',
    value: SECRET_VAL,
    env_file: '.env.local',
    seal: true
  })

  tree = h.rerenderSurface('pane')
  // Secret input is wiped immediately and secret never appears in UI/toasts/clipboard
  const valInputAfter = findAll(tree, n => n.type === 'input' && n.props.type === 'password')[0]
  assert.equal(valInputAfter.props.value, '')
  assert.ok(!collectText(tree).join('\n').includes(SECRET_VAL), 'secret value must never render in UI text')
  assert.ok(!JSON.stringify(mockState.notifications).includes(SECRET_VAL), 'secret value must never enter notifications')

  // Copy ready note copies ONLY the key name continuation message
  const copyReadyBtn = findButton(tree, 'Copy ready note')
  assert.ok(copyReadyBtn, 'Copy ready note button must render after saving secret')
  copyReadyBtn.props.onClick()
  await Promise.resolve()
  assert.deepEqual(mockState.clipboardCalls, ['Configured OPENAI_API_KEY in CipherVault — you can continue.'])
  assert.ok(!mockState.clipboardCalls.join('\n').includes(SECRET_VAL))

  // Hide toggle collapses drawer even while pending prompts exist
  const hideBtn = findButton(tree, 'Hide')
  assert.ok(hideBtn)
  hideBtn.props.onClick()
  tree = h.rerenderSurface('pane')
  assert.equal(findAll(tree, n => n.type === 'form').length, 0, 'Hide button must collapse drawer even with pending prompts')
})

test('error states and input validation fail cleanly without calling POST /set', async () => {
  // Backend down
  const hDown = createHarness({
    handlers: {
      'GET /status': () => { throw new Error('ECONNREFUSED') }
    }
  })
  const downTree = await hDown.renderSurface('pane')
  assert.match(collectText(downTree).join('\n'), /Vault backend unavailable/)

  // Missing binary
  const hNoBin = createHarness({
    handlers: {
      'GET /status': () => ({ binary: 'missing', vault: false })
    }
  })
  const noBinTree = await hNoBin.renderSurface('pane')
  assert.match(collectText(noBinTree).join('\n'), /CipherVault binary not found/)

  // No vault
  const hNoVault = createHarness({
    handlers: {
      'GET /status': () => ({ binary: 'ok', vault: false })
    }
  })
  const noVaultTree = await hNoVault.renderSurface('pane')
  assert.match(collectText(noVaultTree).join('\n'), /No vault in this workspace/)

  // Invalid key validation in Secret Entry Drawer
  const hVal = createHarness({ handlers: defaultHandlers() })
  let tree = await hVal.renderSurface('pane')
  findButton(tree, 'Add secret').props.onClick()
  tree = hVal.rerenderSurface('pane')
  findAll(tree, n => n.type === 'input' && n.props.type === 'text')[0].props.onChange({ target: { value: 'BAD-KEY!' } })
  findAll(tree, n => n.type === 'input' && n.props.type === 'password')[0].props.onChange({ target: { value: 'abc123' } })
  tree = hVal.rerenderSurface('pane')
  await findAll(tree, n => n.type === 'form')[0].props.onSubmit({ preventDefault() {} })
  assert.equal(hVal.restCalls.filter(c => c.endpoint.startsWith('/set')).length, 0)
  assert.ok(mockState.notifications.some(n => n.kind === 'error' && n.message.includes('Invalid key name')))
})

test('failed POST /set and POST /generate surface errors, wipe secret input, and fallback clipboard never rejects', async () => {
  const SECRET_VAL = 'top-secret-fail-case-999'
  const h = createHarness({
    handlers: defaultHandlers({
      'POST /set': () => ({ success: false, error: 'sealed vault requires CLI upgrade' }),
      'POST /generate': () => ({ success: false, error: 'key already exists' })
    })
  })
  let tree = await h.renderSurface('pane')

  // Failed POST /generate does not show Copy ready note
  const genBtn = findAll(tree, n => n.type === 'button' && collectText(n).join('') === 'Generate')[0]
  await genBtn.props.onClick()
  tree = h.rerenderSurface('pane')
  assert.equal(findButton(tree, 'Copy ready note'), undefined)
  assert.ok(mockState.notifications.some(n => n.kind === 'error' && n.message.includes('key already exists')))

  // Failed POST /set still wipes password input and never leaks secret value
  findButton(tree, 'Add secret').props.onClick()
  tree = h.rerenderSurface('pane')
  findAll(tree, n => n.type === 'input' && n.props.type === 'text')[0].props.onChange({ target: { value: 'API_TOKEN' } })
  findAll(tree, n => n.type === 'input' && n.props.type === 'password')[0].props.onChange({ target: { value: SECRET_VAL } })
  tree = h.rerenderSurface('pane')
  await findAll(tree, n => n.type === 'form')[0].props.onSubmit({ preventDefault() {} })
  tree = h.rerenderSurface('pane')
  assert.equal(findAll(tree, n => n.type === 'input' && n.props.type === 'password')[0].props.value, '')
  assert.equal(findButton(tree, 'Copy ready note'), undefined)
  assert.ok(!JSON.stringify(mockState.notifications).includes(SECRET_VAL))

  // Clipboard rejection fallback produces info toast with non-secret ready note (no unhandled rejection)
  const hClip = createHarness({ handlers: defaultHandlers() })
  mockState.clipboardMode = 'reject'
  let clipTree = await hClip.renderSurface('pane')
  const clipGenBtn = findAll(clipTree, n => n.type === 'button' && collectText(n).join('') === 'Generate')[0]
  await clipGenBtn.props.onClick()
  await hClip.settleQueries()
  clipTree = hClip.rerenderSurface('pane')
  findButton(clipTree, 'Copy ready note').props.onClick()
  await new Promise(r => setTimeout(r, 10))
  assert.ok(
    mockState.notifications.some(
      n => n.kind === 'info' && n.message.includes('Configured STRIPE_SECRET_KEY in CipherVault — you can continue.')
    )
  )
})
