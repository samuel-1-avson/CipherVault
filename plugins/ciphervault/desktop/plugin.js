/**
 * CipherVault desktop plugin — live vault pane, status page, palette
 * command, and statusbar chip.
 *
 * Data comes from the plugin's own backend (dashboard/plugin_api.py,
 * mounted at /api/plugins/ciphervault/) which shells out to
 * `ciphervault status --json`. That reports tracked file PATHS and
 * truncated identifiers only — secret values never reach this UI.
 * If the backend or binary is unavailable the pane says so plainly;
 * the agent tools (ciphervault_*) work regardless of this surface.
 */
import { cn, haptic, host, Tip, usePluginI18n, useQuery, useValue, PALETTE_AREA, ROUTES_AREA } from '@hermes/plugin-sdk'
import { useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'ciphervault'
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/

function readyNoteForKey(key) {
  return `Configured ${key} in CipherVault — you can continue.`
}

function useVaultStatus(ctx) {
  const cwd = useValue(host.state.cwd)
  return useQuery({
    queryKey: [ID, 'status', String(cwd || '')],
    retry: false,
    refetchInterval: 15000,
    queryFn: async () => ctx.rest('/status?cwd=' + encodeURIComponent(String(cwd || '')))
  })
}

function useVaultAudit(ctx, enabled) {
  const cwd = useValue(host.state.cwd)
  return useQuery({
    queryKey: [ID, 'audit', String(cwd || '')],
    enabled: Boolean(enabled),
    retry: false,
    refetchInterval: 30000,
    queryFn: async () => ctx.rest('/audit?cwd=' + encodeURIComponent(String(cwd || '')) + '&limit=10')
  })
}

function usePendingPrompts(ctx, enabled) {
  const cwd = useValue(host.state.cwd)
  return useQuery({
    queryKey: [ID, 'pending-prompts', String(cwd || '')],
    enabled: Boolean(enabled),
    retry: false,
    refetchInterval: 10000,
    queryFn: async () => ctx.rest('/pending-prompts?cwd=' + encodeURIComponent(String(cwd || '')))
  })
}

function useEnvHealth(ctx, enabled) {
  const cwd = useValue(host.state.cwd)
  return useQuery({
    queryKey: [ID, 'env-health', String(cwd || '')],
    enabled: Boolean(enabled),
    retry: false,
    refetchInterval: 30000,
    queryFn: async () => ctx.rest('/env-health?cwd=' + encodeURIComponent(String(cwd || '')))
  })
}

function SecretEntryDrawer({
  ctx,
  cwd,
  q,
  pendingQ,
  healthQ,
  open,
  setOpen,
  keyName,
  setKeyName,
  envFile,
  setEnvFile,
  seal,
  setSeal,
  selectedPrompt,
  setSelectedPrompt,
  lastSavedKey,
  setLastSavedKey,
  onCopyReadyNote
}) {
  const t = usePluginI18n(ID)
  const pendingKeys = Array.isArray(pendingQ?.data?.keys) ? pendingQ.data.keys : []
  const [secretValue, setSecretValue] = useState('')
  const [saving, setSaving] = useState(false)

  const isExpanded = open === null ? pendingKeys.length > 0 : Boolean(open)
  const envChoices = ['.env', '.env.local', '.env.development', '.env.production']
  if (envFile && !envChoices.includes(envFile)) {
    envChoices.push(envFile)
  }

  const applyPromptChip = (item) => {
    haptic('tap')
    setOpen(true)
    setSelectedPrompt(item)
    setKeyName(item.name || '')
    if (item.env_file) setEnvFile(item.env_file)
    else if (pendingQ?.data?.env_file) setEnvFile(pendingQ.data.env_file)
    if (typeof item.seal === 'boolean') setSeal(item.seal)
    else if (typeof pendingQ?.data?.seal === 'boolean') setSeal(pendingQ.data.seal)
  }

  const submitSecret = async (e) => {
    if (e && e.preventDefault) e.preventDefault()
    if (saving) return
    const trimmedKey = String(keyName || '').trim()
    if (!ENV_KEY_RE.test(trimmedKey)) {
      host.notify({ kind: 'error', message: t('secretInvalidKey') })
      return
    }
    if (!secretValue) {
      host.notify({ kind: 'error', message: t('secretEmptyVal') })
      return
    }
    setSaving(true)
    try {
      const res = await ctx.rest('/set?cwd=' + encodeURIComponent(String(cwd || '')), {
        method: 'POST',
        body: JSON.stringify({
          key: trimmedKey,
          value: secretValue,
          env_file: envFile || '.env',
          seal: Boolean(seal)
        }),
        headers: { 'Content-Type': 'application/json' }
      })
      if (res && res.success) {
        setSecretValue('')
        setKeyName('')
        setSelectedPrompt(null)
        setLastSavedKey(trimmedKey)
        await Promise.all([
          q?.refetch ? q.refetch() : null,
          pendingQ?.refetch ? pendingQ.refetch() : null,
          healthQ?.refetch ? healthQ.refetch() : null
        ])
        host.notify({ kind: 'success', message: t('secretSavedOk', trimmedKey) })
      } else {
        host.notify({ kind: 'error', message: t('secretSavedErr', res?.error || 'unknown') })
      }
    } catch (err) {
      host.notify({ kind: 'error', message: t('secretSavedErr', String(err?.message || err || 'unknown')) })
    } finally {
      setSecretValue('')
      setSaving(false)
    }
  }

  return jsxs('div', {
    className: 'mt-2 rounded-lg border border-(--ui-stroke-secondary) p-2',
    children: [
      jsxs('div', {
        className: 'flex items-center justify-between gap-2',
        children: [
          jsxs('div', {
            className: 'flex items-center gap-1.5',
            children: [
              jsx('span', {
                className: 'text-[0.6875rem] font-medium uppercase tracking-wide text-(--ui-text-tertiary)',
                children: t('drawerTitle')
              }),
              pendingKeys.length > 0
                ? jsx('span', {
                    className: 'rounded bg-amber-500/20 px-1.5 py-0.5 text-[0.625rem] font-medium text-amber-400',
                    children: t('pendingCount', String(pendingKeys.length))
                  })
                : null
            ]
          }),
          jsx('button', {
            type: 'button',
            className: 'text-[0.6875rem] text-(--ui-text-tertiary) underline hover:text-foreground',
            onClick: () => { haptic('tap'); setOpen(!isExpanded) },
            children: isExpanded ? t('drawerHide') : t('drawerShow')
          })
        ]
      }),
      lastSavedKey
        ? jsxs('div', {
            className: 'mt-1.5 flex items-center justify-between gap-1.5 rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[0.6875rem] text-emerald-300',
            children: [
              jsx('span', {
                className: 'min-w-0 flex-1 truncate',
                title: readyNoteForKey(lastSavedKey),
                children: t('readyNoteBanner', lastSavedKey)
              }),
              jsxs('div', {
                className: 'flex shrink-0 items-center gap-1',
                children: [
                  jsx('button', {
                    type: 'button',
                    className: 'rounded border border-emerald-400/50 px-1.5 py-0.5 text-[0.625rem] font-medium text-emerald-200 hover:bg-emerald-500/20',
                    onClick: () => { haptic('tap'); onCopyReadyNote(lastSavedKey) },
                    children: t('bCopyReadyNote')
                  }),
                  jsx('button', {
                    type: 'button',
                    'aria-label': t('dismiss'),
                    className: 'px-1 text-[0.6875rem] text-emerald-300/80 hover:text-emerald-100',
                    onClick: () => { haptic('tap'); setLastSavedKey('') },
                    children: '×'
                  })
                ]
              })
            ]
          })
        : null,
      pendingKeys.length > 0
        ? jsxs('div', {
            className: 'mt-1.5 flex flex-wrap gap-1',
            children: [
              jsx('span', { className: 'w-full text-[0.6875rem] text-(--ui-text-tertiary)', children: t('pendingHint') }),
              ...pendingKeys.map((item, idx) =>
                jsx('button', {
                  type: 'button',
                  title: item.reason || item.name,
                  className: cn(
                    'rounded border px-1.5 py-0.5 text-[0.6875rem] transition-colors',
                    keyName === item.name
                      ? 'border-amber-400 bg-amber-500/15 text-amber-300'
                      : 'border-(--ui-stroke-secondary) text-(--ui-text-secondary) hover:bg-(--chrome-action-hover)'
                  ),
                  onClick: () => applyPromptChip(item),
                  children: item.expected_prefix ? `${item.name} (${item.expected_prefix}…)` : item.name
                }, `pending-${item.name}-${idx}`)
              )
            ]
          })
        : null,
      isExpanded
        ? jsxs('form', {
            className: 'mt-2 flex flex-col gap-1.5',
            onSubmit: submitSecret,
            children: [
              selectedPrompt && selectedPrompt.reason
                ? jsx('div', {
                    className: 'text-[0.6875rem] leading-snug text-(--ui-text-tertiary)',
                    children: selectedPrompt.reason
                  })
                : null,
              jsx('input', {
                type: 'text',
                value: keyName,
                placeholder: t('secretKeyPlaceholder'),
                autoComplete: 'off',
                className: 'w-full rounded border border-(--ui-stroke-secondary) bg-transparent px-2 py-1 text-xs text-(--ui-text-primary) outline-none focus:border-(--ui-stroke-primary)',
                onChange: e => setKeyName(e.target.value)
              }),
              jsx('input', {
                type: 'password',
                value: secretValue,
                placeholder: t('secretValPlaceholder'),
                autoComplete: 'new-password',
                className: 'w-full rounded border border-(--ui-stroke-secondary) bg-transparent px-2 py-1 text-xs text-(--ui-text-primary) outline-none focus:border-(--ui-stroke-primary)',
                onChange: e => setSecretValue(e.target.value)
              }),
              jsxs('div', {
                className: 'flex items-center justify-between gap-2',
                children: [
                  jsx('select', {
                    value: envFile,
                    className: 'rounded border border-(--ui-stroke-secondary) bg-transparent px-1.5 py-1 text-[0.6875rem] text-(--ui-text-secondary) outline-none',
                    onChange: e => setEnvFile(e.target.value),
                    children: envChoices.map(opt => jsx('option', { value: opt, children: opt }, opt))
                  }),
                  jsxs('label', {
                    className: 'flex items-center gap-1 text-[0.6875rem] text-(--ui-text-secondary)',
                    children: [
                      jsx('input', {
                        type: 'checkbox',
                        checked: seal,
                        onChange: e => setSeal(Boolean(e.target.checked))
                      }),
                      jsx('span', { children: t('secretSealLabel') })
                    ]
                  })
                ]
              }),
              jsx('button', {
                type: 'submit',
                disabled: saving,
                className: cn(
                  'mt-0.5 rounded-md border border-(--ui-stroke-secondary) px-2 py-1 text-xs font-medium',
                  'text-(--ui-text-primary) hover:bg-(--chrome-action-hover)',
                  saving && 'opacity-50 cursor-not-allowed'
                ),
                children: saving ? t('secretSaving') : t('secretSaveBtn')
              })
            ]
          })
        : null
    ]
  })
}

function StatusBody({ ctx }) {
  const t = usePluginI18n(ID)
  const cwd = useValue(host.state.cwd)
  const q = useVaultStatus(ctx)
  const vaultReady = Boolean(q.data && q.data.vault)
  const auditQ = useVaultAudit(ctx, vaultReady)
  const pendingQ = usePendingPrompts(ctx, vaultReady)
  const healthQ = useEnvHealth(ctx, vaultReady)
  const [sealing, setSealing] = useState(false)
  const [generatingKey, setGeneratingKey] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(null)
  const [drawerKeyName, setDrawerKeyName] = useState('')
  const [drawerEnvFile, setDrawerEnvFile] = useState('.env')
  const [drawerSeal, setDrawerSeal] = useState(true)
  const [selectedPrompt, setSelectedPrompt] = useState(null)
  const [lastSavedKey, setLastSavedKey] = useState('')

  const copyText = (text, onSuccess, onFallback) => {
    try {
      const res = host?.clipboard?.writeText ? host.clipboard.writeText(text) : null
      if (res && typeof res.then === 'function') {
        res.then(onSuccess, onFallback)
      } else if (res === true) {
        onSuccess()
      } else {
        onFallback()
      }
    } catch (e) {
      onFallback()
    }
  }
  const copy = (text, label) => copyText(
    text,
    () => host.notify({ kind: 'success', message: t('copied', label) }),
    () => host.notify({ kind: 'info', message: t('ask', label) })
  )
  const copyReadyNote = (key) => {
    const safeKey = String(key || '').trim()
    if (!ENV_KEY_RE.test(safeKey)) return
    const note = readyNoteForKey(safeKey)
    copyText(
      note,
      () => host.notify({ kind: 'success', message: t('readyNoteCopied', safeKey) }),
      () => host.notify({ kind: 'info', message: t('readyNoteAsk', note) })
    )
  }

  const openDrawerForKey = (key) => {
    const pendingKeys = Array.isArray(pendingQ?.data?.keys) ? pendingQ.data.keys : []
    const matched = pendingKeys.find(item => item && item.name === key) || null
    setDrawerOpen(true)
    setDrawerKeyName(String(key || ''))
    setSelectedPrompt(matched)
    if (matched?.env_file) setDrawerEnvFile(matched.env_file)
    else if (pendingQ?.data?.env_file) setDrawerEnvFile(pendingQ.data.env_file)
    if (typeof matched?.seal === 'boolean') setDrawerSeal(matched.seal)
    else if (typeof pendingQ?.data?.seal === 'boolean') setDrawerSeal(pendingQ.data.seal)
  }

  const generateSecret = async (key) => {
    if (generatingKey) return
    const trimmedKey = String(key || '').trim()
    if (!ENV_KEY_RE.test(trimmedKey)) {
      host.notify({ kind: 'error', message: t('secretInvalidKey') })
      return
    }
    setGeneratingKey(trimmedKey)
    try {
      const res = await ctx.rest('/generate?cwd=' + encodeURIComponent(String(cwd || '')), {
        method: 'POST',
        body: JSON.stringify({
          name: trimmedKey,
          format: 'base64url',
          bytes: 32,
          env_file: drawerEnvFile || '.env',
          seal: Boolean(drawerSeal),
          overwrite: false
        }),
        headers: { 'Content-Type': 'application/json' }
      })
      if (res && res.success) {
        const savedName = ENV_KEY_RE.test(String(res.name || '')) ? String(res.name) : trimmedKey
        setLastSavedKey(savedName)
        await Promise.all([
          q?.refetch ? q.refetch() : null,
          pendingQ?.refetch ? pendingQ.refetch() : null,
          healthQ?.refetch ? healthQ.refetch() : null
        ])
        host.notify({ kind: 'success', message: t('secretGenOk', savedName, res.sha256_prefix || '') })
      } else {
        host.notify({ kind: 'error', message: t('secretGenErr', res?.error || 'unknown') })
      }
    } catch (err) {
      host.notify({ kind: 'error', message: t('secretGenErr', String(err?.message || err || 'unknown')) })
    } finally {
      setGeneratingKey(null)
    }
  }

  const sealNow = async () => {
    if (sealing) return
    setSealing(true)
    try {
      const res = await ctx.rest('/seal?cwd=' + encodeURIComponent(String(cwd || '')), { method: 'POST' })
      await q.refetch()
      if (res && res.error) {
        host.notify({ kind: 'error', message: t('sealedErr', res.error) })
      } else {
        host.notify({ kind: 'success', message: t('sealedOk') })
      }
    } catch (e) {
      host.notify({ kind: 'error', message: t('sealedErr', String(e?.message || e || 'unknown')) })
    } finally {
      setSealing(false)
    }
  }
  const btn = (label, onClick, disabled = false) =>
    jsx('button', {
      type: 'button',
      disabled,
      className: cn(
        'rounded-md border border-(--ui-stroke-secondary) px-2 py-1 text-[0.6875rem]',
        'text-(--ui-text-secondary) hover:bg-(--chrome-action-hover) hover:text-foreground',
        disabled && 'opacity-50 cursor-not-allowed'
      ),
      onClick: () => { haptic('tap'); onClick() },
      children: label
    })

  let state
  if (q.isLoading) {
    state = jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: t('loading') })
  } else if (q.isError || !q.data) {
    state = jsxs('div', {
      className: 'rounded-lg border border-(--ui-stroke-secondary) p-2 text-xs',
      children: [
        jsx('div', { className: 'font-medium text-(--ui-text-primary)', children: t('backendDown') }),
        jsx('div', { className: 'mt-1 leading-snug text-(--ui-text-tertiary)', children: t('backendDownSub') })
      ]
    })
  } else if (q.data.binary === 'missing') {
    state = jsxs('div', {
      className: 'rounded-lg border border-(--ui-stroke-secondary) p-2 text-xs',
      children: [
        jsx('div', { className: 'font-medium text-(--ui-text-primary)', children: t('noBinary') }),
        jsx('div', { className: 'mt-1 leading-snug text-(--ui-text-tertiary)', children: t('noBinarySub') })
      ]
    })
  } else if (!q.data.vault) {
    state = jsxs('div', {
      className: 'rounded-lg border border-(--ui-stroke-secondary) p-2 text-xs',
      children: [
        jsx('div', { className: 'font-medium text-(--ui-text-primary)', children: t('noVault') }),
        jsx('div', { className: 'mt-1 leading-snug text-(--ui-text-tertiary)', children: t('noVaultSub') })
      ]
    })
  } else {
    const d = q.data
    const row = (label, value) => jsxs('div', {
      className: 'flex items-baseline justify-between gap-2 py-0.5',
      children: [
        jsx('span', { className: 'text-[0.6875rem] text-(--ui-text-tertiary)', children: label }),
        jsx('span', { className: 'text-xs font-medium text-(--ui-text-primary)', children: String(value ?? '—') })
      ]
    }, label)
    const paths = Array.isArray(d.tracked_paths) ? d.tracked_paths : []
    const rawProfiles = Array.isArray(d.policy_profiles) ? d.policy_profiles : []
    const policyProfiles = rawProfiles
      .map(item => (typeof item === 'string' ? { name: item } : item))
      .filter(item => item && typeof item === 'object' && item.name)
    const policyError = typeof d.policy_error === 'string' && d.policy_error ? d.policy_error : ''
    const sealedLabel = d.working_tree_sealed ? 'sealed (0B on disk)' : 'plaintext on disk'
    const auditEntries = Array.isArray(auditQ.data?.entries) ? auditQ.data.entries : []
    const auditVerified = Boolean(auditQ.data?.success && auditQ.data?.verification?.ok)
    const missingKeys = Array.isArray(healthQ.data?.missing_in_vault) ? healthQ.data.missing_in_vault : []
    const anomalies = Array.isArray(healthQ.data?.value_anomalies) ? healthQ.data.value_anomalies : []
    state = jsxs('div', {
      children: [
        jsxs('div', {
          className: 'rounded-lg border border-(--ui-stroke-secondary) p-2',
          children: [
            row(t('fVault'), d.vault_id_short || '—'),
            row(t('fHead'), d.active_head_short || t('none')),
            row(t('fSealed'), sealedLabel),
            row(t('fFiles'), d.tracked_files ?? paths.length),
            row(t('fOperators'), d.operators ?? 0),
            row(t('fEpoch'), d.current_epoch ?? '—'),
            row(t('fCli'), d.cli_version || '—'),
            row(
              t('fProfiles'),
              policyError
                ? t('policyErrShort')
                : (policyProfiles.length ? t('profilesCount', String(policyProfiles.length)) : t('none'))
            ),
            policyError
              ? jsx('div', {
                  className: 'mt-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-1 text-[0.6875rem] text-amber-300',
                  children: t('policyErrMsg', policyError)
                })
              : null,
            policyProfiles.length > 0
              ? jsxs('div', {
                  className: 'mt-1.5 border-t border-(--ui-stroke-secondary) pt-1.5',
                  children: [
                    jsx('div', {
                      className: 'text-[0.625rem] font-medium uppercase tracking-wide text-(--ui-text-tertiary)',
                      children: t('profilesTitle')
                    }),
                    jsx('div', {
                      className: 'mt-1 flex flex-col gap-1',
                      children: policyProfiles.map((p, idx) => {
                        const keyCount = typeof p.allow_keys_count === 'number'
                          ? p.allow_keys_count
                          : (Array.isArray(p.allow_keys) ? p.allow_keys.length : 0)
                        const modeLabel = p.proxy
                          ? 'proxy'
                          : p.no_net === true
                            ? 'no-net'
                            : p.no_net === false
                              ? 'net'
                              : 'default'
                        const modeClass = p.proxy
                          ? 'border-sky-400/40 bg-sky-500/10 text-sky-300'
                          : p.no_net === true
                            ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300'
                            : 'border-amber-400/40 bg-amber-500/10 text-amber-300'
                        const tipParts = [p.description || '']
                        if (Array.isArray(p.commands) && p.commands.length) tipParts.push(`cmds: ${p.commands.join(', ')}`)
                        if (Array.isArray(p.allow_keys) && p.allow_keys.length) tipParts.push(`keys: ${p.allow_keys.join(', ')}`)
                        if (Array.isArray(p.require_keys) && p.require_keys.length) tipParts.push(`req: ${p.require_keys.join(', ')}`)
                        if (Array.isArray(p.upstreams) && p.upstreams.length) tipParts.push(`upstreams: ${p.upstreams.join(', ')}`)
                        return jsxs('div', {
                          title: tipParts.filter(Boolean).join(' • ') || p.name,
                          className: 'flex items-center justify-between gap-1.5 rounded border border-(--ui-stroke-secondary) px-1.5 py-1 text-[0.6875rem]',
                          children: [
                            jsxs('div', {
                              className: 'min-w-0 flex-1',
                              children: [
                                jsx('div', {
                                  className: 'truncate font-medium text-(--ui-text-primary)',
                                  children: p.name
                                }),
                                p.description
                                  ? jsx('div', {
                                      className: 'truncate text-[0.625rem] text-(--ui-text-tertiary)',
                                      children: p.description
                                    })
                                  : null
                              ]
                            }),
                            jsxs('div', {
                              className: 'flex shrink-0 items-center gap-1',
                              children: [
                                jsx('span', {
                                  className: cn('rounded border px-1 py-0.5 text-[0.625rem] font-medium', modeClass),
                                  children: modeLabel
                                }),
                                jsx('span', {
                                  className: 'text-[0.625rem] text-(--ui-text-tertiary)',
                                  children: t('profileKeys', String(keyCount))
                                })
                              ]
                            })
                          ]
                        }, `profile-${p.name}-${idx}`)
                      })
                    })
                  ]
                })
              : null
          ]
        }),
        !d.working_tree_sealed
          ? jsx('div', {
              className: 'mt-2',
              children: btn(sealing ? t('sealing') : t('bSeal'), sealNow, sealing)
            })
          : null,
        jsx(SecretEntryDrawer, {
          ctx,
          cwd,
          q,
          pendingQ,
          healthQ,
          open: drawerOpen,
          setOpen: setDrawerOpen,
          keyName: drawerKeyName,
          setKeyName: setDrawerKeyName,
          envFile: drawerEnvFile,
          setEnvFile: setDrawerEnvFile,
          seal: drawerSeal,
          setSeal: setDrawerSeal,
          selectedPrompt,
          setSelectedPrompt,
          lastSavedKey,
          setLastSavedKey,
          onCopyReadyNote: copyReadyNote
        }),
        healthQ.data && healthQ.data.success
          ? jsxs('div', {
              className: 'mt-2 rounded-lg border border-(--ui-stroke-secondary) p-2',
              children: [
                jsxs('div', {
                  className: 'flex items-center justify-between gap-2',
                  children: [
                    jsx('span', { className: 'text-[0.6875rem] font-medium uppercase tracking-wide text-(--ui-text-tertiary)', children: t('envHealthTitle') }),
                    jsx('span', {
                      className: cn(
                        'text-[0.6875rem] font-medium',
                        missingKeys.length === 0 && anomalies.length === 0
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      ),
                      children:
                        missingKeys.length === 0 && anomalies.length === 0
                          ? t('envHealthy')
                          : `${missingKeys.length} missing · ${anomalies.length} lint`
                    })
                  ]
                }),
                ...missingKeys.slice(0, 6).map(k => {
                  const isGen = generatingKey === k
                  const anyGen = Boolean(generatingKey)
                  return jsxs('div', {
                    className: 'flex items-center justify-between gap-1.5 py-0.5',
                    children: [
                      jsx('span', {
                        className: 'min-w-0 flex-1 truncate text-[0.6875rem] text-amber-300',
                        title: k,
                        children: `missing: ${k}`
                      }),
                      jsxs('div', {
                        className: 'flex shrink-0 items-center gap-1',
                        children: [
                          jsx('button', {
                            type: 'button',
                            disabled: isGen,
                            className: cn(
                              'rounded border border-(--ui-stroke-secondary) px-1.5 py-0.5 text-[0.625rem] text-(--ui-text-secondary) hover:bg-(--chrome-action-hover) hover:text-foreground',
                              isGen && 'opacity-50 cursor-not-allowed'
                            ),
                            onClick: () => { haptic('tap'); openDrawerForKey(k) },
                            children: t('bFill')
                          }),
                          jsx('button', {
                            type: 'button',
                            disabled: anyGen,
                            className: cn(
                              'rounded border border-amber-400/50 px-1.5 py-0.5 text-[0.625rem] font-medium text-amber-200 hover:bg-amber-500/20',
                              anyGen && 'opacity-50 cursor-not-allowed'
                            ),
                            onClick: () => { haptic('tap'); generateSecret(k) },
                            children: isGen ? t('bGenerating') : t('bGenerate')
                          })
                        ]
                      })
                    ]
                  }, `m-${k}`)
                }),
                missingKeys.length > 6
                  ? jsx('div', {
                      className: 'text-[0.6875rem] text-(--ui-text-quaternary)',
                      children: t('more', String(missingKeys.length - 6))
                    })
                  : null,
                ...anomalies.slice(0, 4).map((a, idx) => jsx('div', {
                  className: 'truncate py-0.5 text-[0.6875rem] text-amber-300',
                  children: `${a.key}: ${a.issue}`
                }, `a-${a.file || ''}-${a.key}-${a.issue}-${idx}`))
              ]
            })
          : null,
        paths.length
          ? jsxs('div', {
              className: 'mt-2',
              children: [
                jsx('div', { className: 'text-[0.6875rem] font-medium uppercase tracking-wide text-(--ui-text-tertiary)', children: t('tracked') }),
                ...paths.slice(0, 12).map(p => jsx('div', {
                  className: 'truncate py-0.5 text-xs text-(--ui-text-secondary)', children: p
                }, p)),
                paths.length > 12
                  ? jsx('div', { className: 'text-[0.6875rem] text-(--ui-text-quaternary)', children: t('more', String(paths.length - 12)) })
                  : null
              ]
            })
          : null,
        auditQ.data
          ? jsxs('div', {
              className: 'mt-2 rounded-lg border border-(--ui-stroke-secondary) p-2',
              children: [
                jsxs('div', {
                  className: 'flex items-center justify-between gap-2',
                  children: [
                    jsx('span', { className: 'text-[0.6875rem] font-medium uppercase tracking-wide text-(--ui-text-tertiary)', children: t('auditTitle') }),
                    jsx('span', {
                      className: cn('text-[0.6875rem] font-medium', auditVerified ? 'text-emerald-400' : 'text-amber-400'),
                      children: auditVerified ? t('auditVerified') : t('auditFailed')
                    })
                  ]
                }),
                ...auditEntries.slice(0, 5).map((e, idx) => jsx('div', {
                  className: 'truncate py-0.5 text-[0.6875rem] text-(--ui-text-secondary)',
                  children: `${e.tool || 'tool'} • ${e.decision || ''}${e.path ? ' (' + e.path + ')' : ''}`
                }, e.id != null
                  ? `audit-${e.id}`
                  : (e.entry_hash ? `audit-${e.entry_hash}` : `audit-${e.timestamp || ''}-${e.tool || 'tool'}-${e.decision || ''}-${idx}`)))
              ]
            })
          : null
      ]
    })
  }

  return jsxs('div', {
    className: 'flex flex-col gap-2',
    children: [
      state,
      jsxs('div', {
        className: 'mt-1 flex flex-wrap gap-1.5',
        children: [
          btn(t('bScan'), () => copy('Scan my workspace for secret sprawl with ciphervault_scan (masked).', 'scan')),
          btn(t('bRun'), () => copy('Run my command with secrets in RAM via ciphervault_run; keep output scrubbed.', 'run')),
          btn(t('bPush'), () => copy('Snapshot my tracked secrets with ciphervault_push (local).', 'push')),
          btn(t('bDrill'), () => copy('Prove my recovery works with ciphervault_recovery_drill using my kit FILE PATH (never its contents).', 'drill'))
        ]
      }),
      jsx('button', {
        type: 'button',
        className: 'self-start text-[0.6875rem] text-(--ui-text-tertiary) underline hover:text-foreground',
        onClick: () => {
          haptic('tap')
          q.refetch()
          if (vaultReady) {
            if (auditQ?.refetch) auditQ.refetch()
            if (pendingQ?.refetch) pendingQ.refetch()
            if (healthQ?.refetch) healthQ.refetch()
          }
        },
        children: t('refresh')
      })
    ]
  })
}

function VaultPane({ ctx }) {
  const t = usePluginI18n(ID)
  const cwd = useValue(host.state.cwd)
  return jsxs('div', {
    className: 'flex h-full flex-col gap-2 overflow-y-auto p-3 text-sm',
    children: [
      jsx('div', { className: 'text-xs font-semibold uppercase tracking-wide text-(--ui-text-tertiary)', children: t('paneTitle') }),
      jsx('div', {
        className: 'truncate rounded-lg border border-(--ui-stroke-secondary) p-2 text-xs text-(--ui-text-secondary)',
        children: t('cwd', String(cwd || '—'))
      }),
      jsx(ExplorerLink, {}),
      jsx(StatusBody, { ctx }),
      jsx('div', { className: 'mt-auto pt-2 text-[0.6875rem] leading-snug text-(--ui-text-quaternary)', children: t('foot') })
    ]
  })
}

function VaultPage({ ctx }) {
  const t = usePluginI18n(ID)
  return jsxs('main', {
    className: 'h-full overflow-auto p-5 text-sm text-(--ui-text-primary)',
    children: [
      jsx('h1', { className: 'text-xl font-semibold', children: t('pageTitle') }),
      jsx('p', { className: 'mt-1 max-w-prose text-(--ui-text-secondary)', children: t('pageSub') }),
      jsx(ExplorerLink, {}),
      jsx('div', { className: 'mt-4 max-w-md', children: jsx(StatusBody, { ctx }) })
    ]
  })
}

const EXPLORER_ROUTE = '/ciphervault/explorer'
const EXPLORER_WEB_URL = 'https://vault.cipherv.online/#explorer'
const EXPLORER_BUTTON = 'rounded-md border border-(--ui-stroke-secondary) px-3 py-1.5 text-xs font-medium hover:bg-(--chrome-action-hover) focus-visible:outline focus-visible:outline-2 disabled:opacity-50'
const EXPLORER_CARD = 'min-w-0 rounded-lg border border-(--ui-stroke-secondary) p-4'
const EXPLORER_MUTED = 'text-xs leading-relaxed text-(--ui-text-secondary)'

function ExplorerLink() {
  return jsx('button', {
    type: 'button', className: EXPLORER_BUTTON + ' self-start',
    onClick: () => host.navigate(EXPLORER_ROUTE),
    children: 'Open Network Explorer',
  })
}

function explorerCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : '—'
}

function explorerHash(value) {
  const hash = typeof value === 'string' ? value : ''
  return hash.length > 26 ? hash.slice(0, 12) + '…' + hash.slice(-8) : hash || '—'
}

function explorerDate(value) {
  if (value == null) return 'Time unavailable'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString()
}

function explorerRows(rows, label) {
  return jsx('ul', {
    className: 'divide-y divide-(--ui-stroke-secondary)',
    'aria-label': label,
    children: rows,
  })
}

function ExplorerOverview({ data, operatorFilter }) {
  const [receipt, setReceipt] = useState(null)
  const operators = Array.isArray(data.operators) ? data.operators : []
  const anchors = Array.isArray(data.anchors) ? data.anchors : []
  const reachable = explorerCount(data.counts?.reachable)
  const total = explorerCount(data.counts?.total)
  const needle = operatorFilter.trim().toLowerCase()
  const visible = operators.filter(row => [row.operator_id, row.display_name, row.region]
    .some(value => String(value || '').toLowerCase().includes(needle)))
  const selected = receipt ? anchors.find(row => (row.tx_hash_hex || row.tx_hash || row.commitment_hex) === receipt) : null
  return jsxs('div', {
    className: 'grid min-w-0 gap-3',
    children: [
      jsxs('div', { className: 'grid grid-cols-1 gap-3 sm:grid-cols-2', children: [
        jsxs('section', { className: EXPLORER_CARD, children: [
          jsx('h2', { className: 'font-semibold', children: 'Storage operators' }),
          jsx('p', { className: 'mt-1 text-2xl tabular-nums', children: `${reachable} / ${total} responding` }),
          typeof total === 'number' && total > 0 && typeof reachable === 'number'
            ? jsx('meter', { className: 'w-full', min: 0, max: total, value: Math.min(total, reachable), 'aria-label': 'Responding operators' }) : null,
          jsx('p', { className: EXPLORER_MUTED, children: explorerDate(data.observed_at_utc) }),
        ] }),
        jsxs('section', { className: EXPLORER_CARD, children: [
          jsx('h2', { className: 'font-semibold', children: 'Public checkpoints' }),
          jsx('p', { className: 'mt-1 text-2xl tabular-nums', children: explorerCount(data.feed?.count) }),
          jsx('p', { className: EXPLORER_MUTED, children: data.feed?.status === 'unconfigured'
            ? 'Feed not configured' : data.feed?.status === 'unavailable' ? 'Feed unavailable' : 'Published anchor receipts' }),
        ] }),
      ] }),
      jsxs('section', { className: EXPLORER_CARD, children: [
        jsx('h2', { className: 'mb-2 font-semibold', children: 'Operators' }),
        visible.length ? explorerRows(visible.map((row, index) => jsxs('li', {
          className: 'flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2',
          children: [
            jsx('span', { className: 'break-all', children: row.display_name || row.operator_id || 'Operator' }),
            jsx('span', { className: EXPLORER_MUTED, children: [
              row.status === 'reachable' || row.status === 'online' || row.online === true ? 'Responding' : 'No response',
              row.region, Number.isFinite(row.latency_ms) ? `${row.latency_ms} ms` : null,
            ].filter(Boolean).join(' · ') }),
          ],
        }, String(row.operator_id || index))), 'Operators') :
          jsx('p', { className: EXPLORER_MUTED, children: data.operators_available
            ? (operators.length ? 'No operators match that filter.' : 'No operators reported.') : 'Operator details are unavailable.' }),
      ] }),
      jsxs('section', { className: EXPLORER_CARD, children: [
        jsx('h2', { className: 'mb-2 font-semibold', children: 'Anchor receipts' }),
        anchors.length ? explorerRows(anchors.map((row, index) => {
          const id = row.tx_hash_hex || row.tx_hash || row.commitment_hex
          const height = row.reported_block_number ?? row.block_number
          return jsxs('li', { className: 'flex flex-wrap items-baseline justify-between gap-2 py-2', children: [
            jsx('button', { type: 'button', className: EXPLORER_BUTTON + ' font-mono', title: id,
              disabled: !id, onClick: () => setReceipt(id), children: explorerHash(id) }),
            jsx('span', { className: EXPLORER_MUTED, children: [
              Number.isSafeInteger(height) ? 'Block #' + height : null, row.finality_status || 'unverified',
            ].filter(Boolean).join(' · ') }),
          ] }, String(id || index) + ':' + index)
        }), 'Anchor receipts') : jsx('p', { className: EXPLORER_MUTED, children: data.anchors_available
          ? 'No anchor receipts are available.' : 'Anchor receipts are unavailable.' }),
        selected ? jsxs('div', { className: 'mt-3 break-all text-xs', role: 'status', children: [
          jsx('p', { className: 'font-mono', children: selected.tx_hash_hex || selected.tx_hash || 'Receipt hash unavailable' }),
          jsx('p', { className: EXPLORER_MUTED, children: selected.commitment_hex
            ? 'Commitment ' + selected.commitment_hex : 'Commitment unavailable' }),
        ] }) : null,
      ] }),
    ],
  })
}

function ExplorerObject({ data }) {
  if (data.state !== 'ready') return jsx('p', { role: 'alert', children: data.error || 'Object lookup unavailable.' })
  const quorum = data.quorum || {}
  return jsxs('section', { className: EXPLORER_CARD, children: [
    jsx('h2', { className: 'font-semibold', children: quorum.satisfied === true ? 'Quorum reported' : 'Quorum shortfall' }),
    jsx('code', { className: 'block break-all text-xs', children: data.cid }),
    jsx('p', { className: EXPLORER_MUTED, children: `${explorerCount(quorum.present)} present · ${explorerCount(quorum.required)} required · ${explorerDate(data.checked_at_utc)}` }),
    explorerRows((data.replicas || []).map((row, index) => jsx('li', {
      className: 'break-all py-2', children: [row.operator_id || row.endpoint, row.status,
        Number.isFinite(row.latency_ms) ? row.latency_ms + ' ms' : null].filter(Boolean).join(' · '),
    }, String(index))), 'Replica reports'),
    jsx('p', { className: EXPLORER_MUTED, children: 'Operators report presence. Object bytes are not downloaded.' }),
  ] })
}

function ExplorerChain({ data, onSearch }) {
  if (data.state === 'empty') return jsx('p', { className: EXPLORER_MUTED, children: 'No local blocks. Anchor a snapshot to start this ledger.' })
  if (data.error) return jsx('p', { role: 'alert', children: data.error })
  const detail = data.detail
  return jsxs('section', { className: EXPLORER_CARD, children: [
    jsx('h2', { className: 'font-semibold', children: 'Local CipherChain' }),
    jsx('p', { className: EXPLORER_MUTED, children: data.solo
      ? 'Solo ledger. One validator per block.' : 'Verified against the saved genesis validator set.' }),
    data.state === 'not_found' ? jsx('p', { role: 'status', children: 'No block or commitment matched that search.' }) : null,
    detail?.block ? jsxs('div', { className: 'my-3 grid gap-2 break-all text-xs', children: [
      jsx('h3', { className: 'font-semibold', children: 'Block #' + detail.block.height }),
      jsx('code', { children: detail.block.hash }),
      jsx('p', { children: `${explorerDate(detail.block.timestamp_ms)} · ${detail.block.timestamp_signed ? 'Signed time' : 'Unsigned time'}` }),
      jsx('p', { children: 'Transaction root ' + detail.transaction_root }),
      jsx('p', { children: 'Parent ' + detail.parent_hash }),
      jsxs('details', { children: [
        jsx('summary', { children: 'Validator keys' }),
        explorerRows((detail.signers || []).map((key, index) => jsx('li', { children: key }, String(index))), 'Signers'),
      ] }),
      detail.inclusion ? jsx('p', { role: 'status', children: `Inclusion verified at index ${detail.inclusion.index} (${detail.inclusion.proof_steps} proof steps).` }) : null,
      (detail.commitments || []).map((commitment, index) => jsx('button', { type: 'button', className: EXPLORER_BUTTON,
        title: commitment, onClick: () => onSearch(commitment), children: 'Verify ' + explorerHash(commitment) }, String(index))),
    ] }) : null,
    explorerRows((data.blocks || []).map((block, index) => jsxs('li', { className: 'flex flex-wrap items-center justify-between gap-2 py-2', children: [
      jsx('button', { type: 'button', className: EXPLORER_BUTTON, onClick: () => onSearch(String(block.height)), children: 'Block #' + block.height }),
      jsx('code', { title: block.hash, children: explorerHash(block.hash) }),
      jsx('span', { className: EXPLORER_MUTED, children: `${explorerCount(block.commitments)} commitments · ${explorerCount(block.signatures)} signatures` }),
    ] }, String(index))), 'Recent blocks'),
  ] })
}

function ExplorerPage({ ctx }) {
  const cwd = String(useValue(host.state.cwd) || '')
  const [mode, setMode] = useState('network')
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const [operatorFilter, setOperatorFilter] = useState('')
  const network = useQuery({ queryKey: [ID, 'explorer'], enabled: mode === 'network', retry: false,
    staleTime: 30000, refetchOnWindowFocus: false,
    queryFn: () => ctx.rest('/explorer', { timeoutMs: 12000 }) })
  const lookup = useQuery({ queryKey: [ID, 'explorer-object', query], enabled: mode === 'network' && Boolean(query),
    retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
    queryFn: () => ctx.rest('/explorer/object?cid=' + encodeURIComponent(query), { timeoutMs: 12000 }) })
  const chain = useQuery({ queryKey: [ID, 'explorer-chain', cwd, query], enabled: mode === 'chain',
    retry: false, refetchOnWindowFocus: false,
    queryFn: () => ctx.rest('/explorer/chain?cwd=' + encodeURIComponent(cwd) + '&query=' + encodeURIComponent(query), { timeoutMs: 18000 }) })
  const current = mode === 'network' ? network : chain
  function switchMode(next) {
    setMode(next)
    setQuery('')
    setDraft('')
  }
  function search(value) {
    const next = value.trim()
    if (!next) return
    if (query === next) (mode === 'network' ? lookup : chain).refetch()
    else setQuery(next)
  }
  return jsxs('main', { className: 'h-full overflow-auto p-4 text-sm text-(--ui-text-primary) sm:p-6', children: [
    jsxs('div', { className: 'mx-auto grid max-w-5xl gap-4', children: [
      jsxs('header', { className: 'flex flex-wrap items-start justify-between gap-3', children: [
        jsxs('div', { children: [
          jsx('h1', { className: 'text-2xl font-semibold tracking-tight', children: 'Network Explorer' }),
          jsx('p', { className: EXPLORER_MUTED, children: 'Inspect operators, encrypted object presence, and the local ledger.' }),
        ] }),
        jsx('button', { type: 'button', className: EXPLORER_BUTTON, onClick: () => host.navigate('/ciphervault'), children: 'Vault status' }),
      ] }),
      jsxs('nav', { className: 'flex flex-wrap gap-2', 'aria-label': 'Explorer views', children: [
        jsx('button', { type: 'button', className: EXPLORER_BUTTON, 'aria-pressed': mode === 'network',
          onClick: () => switchMode('network'), children: 'Public network' }),
        jsx('button', { type: 'button', className: EXPLORER_BUTTON, 'aria-pressed': mode === 'chain',
          onClick: () => switchMode('chain'), children: 'Local CipherChain' }),
        jsx('button', { type: 'button', className: EXPLORER_BUTTON, disabled: current.isFetching,
          onClick: () => current.refetch(), children: current.isFetching ? 'Refreshing…' : 'Refresh' }),
        ctx.os?.openExternal ? jsx('button', {
          type: 'button', className: EXPLORER_BUTTON,
          onClick: async () => {
            if (!await ctx.os.openExternal(EXPLORER_WEB_URL)) {
              host.notify({ kind: 'warning', message: 'Open vault.cipherv.online in your browser.' })
            }
          },
          children: 'Open web explorer',
        }) : jsx('a', { className: EXPLORER_BUTTON, href: EXPLORER_WEB_URL, target: '_blank', rel: 'noreferrer noopener', children: 'Open web explorer' }),
      ] }),
      jsxs('form', { role: 'search', className: 'flex flex-wrap gap-2', onSubmit: event => { event.preventDefault(); search(draft) }, children: [
        jsx('input', { type: 'search', value: draft, required: true, maxLength: 66, autoComplete: 'off', spellCheck: false,
          onChange: event => setDraft(event.currentTarget.value),
          className: 'min-w-0 flex-1 rounded-md border border-(--ui-stroke-secondary) bg-transparent px-3 py-2',
          'aria-label': mode === 'network' ? 'Object CID' : 'Block height, hash, or commitment',
          placeholder: mode === 'network' ? 'Object CID' : 'Block height, hash, or commitment' }),
        jsx('button', { type: 'submit', className: EXPLORER_BUTTON, children: mode === 'network' ? 'Check replicas' : 'Find block' }),
        query ? jsx('button', { type: 'button', className: EXPLORER_BUTTON, onClick: () => { setQuery(''); setDraft('') }, children: 'Clear' }) : null,
      ] }),
      mode === 'network' ? jsxs('div', { className: 'grid gap-3', children: [
        jsx('p', { className: EXPLORER_MUTED, children: 'Object lookups send the entered CID to the public explorer.' }),
        query && lookup.isFetching ? jsx('p', { role: 'status', children: 'Checking operators…' }) : null,
        query && lookup.isError ? jsx('p', { role: 'alert', children: 'Object lookup unavailable. Submit it again to retry.' }) : null,
        query && lookup.data ? jsx(ExplorerObject, { data: lookup.data }) : null,
        jsx('input', { type: 'search', value: operatorFilter, maxLength: 100,
          className: 'rounded-md border border-(--ui-stroke-secondary) bg-transparent px-3 py-2',
          onChange: event => setOperatorFilter(event.currentTarget.value), 'aria-label': 'Filter operators', placeholder: 'Filter operators by name, ID, or region' }),
      ] }) : null,
      current.isLoading ? jsx('p', { role: 'status', children: mode === 'network' ? 'Loading network…' : 'Verifying local ledger…' }) : null,
      current.isError || (mode === 'network' && current.data?.state === 'unavailable')
        ? jsx('p', { role: 'alert', children: 'Explorer data is unavailable. Use Refresh to retry.' }) : null,
      mode === 'network' && current.data?.state === 'ready' ? jsx(ExplorerOverview, { data: current.data, operatorFilter }) : null,
      mode === 'chain' && current.data ? jsx(ExplorerChain, { data: current.data, onSearch: search }) : null,
    ] }),
  ] })
}

function VaultChip({ ctx }) {
  const t = usePluginI18n(ID)
  const q = useVaultStatus(ctx)
  const ok = q.data && q.data.binary !== 'missing' && q.data.vault
  const sealed = Boolean(ok && q.data.working_tree_sealed)
  const color = q.isLoading ? 'bg-zinc-400' : sealed ? 'bg-emerald-400' : 'bg-amber-400'
  return jsx(Tip, {
    label: t('chipTip'),
    children: jsxs('button', {
      type: 'button',
      className: cn(
        'inline-flex h-full items-center gap-1.5 px-1.5 text-[0.6875rem] transition-colors',
        'text-(--ui-text-tertiary) hover:bg-(--chrome-action-hover) hover:text-foreground'
      ),
      onClick: () => {
        haptic('tap')
        host.navigate('/ciphervault')
      },
      children: [
        jsx('span', { className: 'inline-block h-1.5 w-1.5 rounded-full ' + color }),
        jsx('span', { children: 'cv • vault' })
      ]
    })
  })
}

export default {
  id: ID,
  name: 'CipherVault',
  register(ctx) {
    ctx.i18n.register({
      en: {
        paneTitle: 'CipherVault secrets',
        pageTitle: 'CipherVault',
        pageSub: 'Zero-knowledge secret backup for this workspace. Status below comes from `ciphervault status --json` — tracked paths and truncated IDs only; values never leave the CLI.',
        cwd: c => `workspace: ${c}`,
        loading: 'Loading vault status…',
        backendDown: 'Vault backend unavailable',
        backendDownSub: 'The plugin API did not answer. The ciphervault_* agent tools still work in chat.',
        noBinary: 'CipherVault binary not found',
        noBinarySub: 'Set CIPHERVAULT_BIN to a compatible CLI (source build), then run `hermes ciphervault doctor`.',
        noVault: 'No vault in this workspace',
        noVaultSub: 'Run `ciphervault init` here, then `ciphervault track .env` and `ciphervault push --local`.',
        fVault: 'Vault', fHead: 'Head', fSealed: 'Working tree', fFiles: 'Tracked files', fOperators: 'Operators', fEpoch: 'Epoch', fCli: 'CLI', fProfiles: 'Policy profiles',
        profilesTitle: 'Active policy profiles',
        profilesCount: n => `${n} active`,
        profileKeys: n => `${n} keys`,
        policyErrShort: 'invalid policy.toml',
        policyErrMsg: e => `Policy parse error: ${e}`,
        bSeal: 'Seal & shred .env',
        sealing: 'Sealing…',
        sealedOk: 'Working tree sealed — plaintext .env shredded.',
        sealedErr: e => `Seal failed: ${e}`,
        drawerTitle: 'Secret entry',
        drawerShow: 'Add secret',
        drawerHide: 'Hide',
        pendingCount: n => `${n} requested`,
        pendingHint: 'Agent requested keys (click to fill):',
        secretKeyPlaceholder: 'KEY_NAME (e.g. OPENAI_API_KEY)',
        secretValPlaceholder: 'Secret value (never enters chat)',
        secretSealLabel: 'Seal & shred',
        secretSaveBtn: 'Save to Vault',
        secretSaving: 'Saving…',
        secretInvalidKey: 'Invalid key name (use A-Z, 0-9, _).',
        secretEmptyVal: 'Secret value cannot be empty.',
        secretSavedOk: k => `${k} encrypted & saved to vault.`,
        secretSavedErr: e => `Save failed: ${e}`,
        secretGenOk: (k, h) => h ? `${k} generated & saved to vault (sha256: ${h}).` : `${k} generated & saved to vault.`,
        secretGenErr: e => `Generate failed: ${e}`,
        envHealthTitle: 'Env Health',
        envHealthy: 'healthy',
        bFill: 'Fill',
        bGenerate: 'Generate',
        bGenerating: 'Generating…',
        readyNoteBanner: k => `Saved ${k} in vault.`,
        bCopyReadyNote: 'Copy ready note',
        readyNoteCopied: k => `Ready note copied for ${k} — paste it in chat to continue.`,
        readyNoteAsk: note => `Tell Hermes: ${note}`,
        dismiss: 'Dismiss',
        auditTitle: 'Recent audit trail',
        auditVerified: 'Signature verified',
        auditFailed: 'Verification failed',
        none: 'none yet',
        tracked: 'Tracked paths',
        more: n => `+${n} more`,
        bScan: 'Copy scan prompt',
        bRun: 'Copy run prompt',
        bPush: 'Copy push prompt',
        bDrill: 'Copy drill prompt',
        refresh: 'Refresh',
        copied: l => `Prompt copied — paste it to Hermes (${l}).`,
        ask: l => `Ask Hermes: use ciphervault tool (${l}) — clipboard unavailable.`,
        foot: 'Values never print. Operators see ciphertext only. Binary via binary_path, $CIPHERVAULT_BIN, or PATH.',
        chipTip: 'CipherVault — open vault status'
      }
    })

    ctx.register({
      id: 'pane',
      area: 'panes',
      title: 'ciphervault',
      data: { placement: 'right', width: '300px' },
      render: () => jsx(VaultPane, { ctx })
    })

    ctx.register({
      id: 'page',
      area: ROUTES_AREA,
      data: { path: '/ciphervault' },
      render: () => jsx(VaultPage, { ctx })
    })
    ctx.register({
      id: 'explorer',
      area: ROUTES_AREA,
      data: { path: EXPLORER_ROUTE },
      render: () => jsx(ExplorerPage, { ctx })
    })
    ctx.register({
      id: 'explorer-open',
      area: PALETTE_AREA,
      data: { id: 'ciphervault.explorer', label: 'CipherVault: Network Explorer',
        keywords: ['network', 'cipherchain', 'operator', 'checkpoint'],
        run: () => host.navigate(EXPLORER_ROUTE) },
      render: () => null
    })

    ctx.register({
      id: 'chip',
      area: 'statusBar.right',
      order: 130,
      render: () => jsx(VaultChip, { ctx })
    })

    ctx.register({
      id: 'open',
      area: PALETTE_AREA,
      data: {
        id: 'ciphervault.open',
        label: 'CipherVault: vault status',
        keywords: ['cipher', 'vault', 'secrets', 'backup'],
        run: () => host.navigate('/ciphervault')
      },
      render: () => null
    })
  }
}
