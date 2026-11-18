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

function SecretEntryDrawer({ ctx, cwd, q, pendingQ }) {
  const t = usePluginI18n(ID)
  const pendingKeys = Array.isArray(pendingQ.data?.keys) ? pendingQ.data.keys : []
  const [open, setOpen] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [secretValue, setSecretValue] = useState('')
  const [envFile, setEnvFile] = useState('.env')
  const [seal, setSeal] = useState(true)
  const [saving, setSaving] = useState(false)
  const [selectedPrompt, setSelectedPrompt] = useState(null)

  const isExpanded = open || pendingKeys.length > 0
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
    if (typeof item.seal === 'boolean') setSeal(item.seal)
  }

  const submitSecret = async (e) => {
    if (e && e.preventDefault) e.preventDefault()
    if (saving) return
    const trimmedKey = String(keyName || '').trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmedKey)) {
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
        await Promise.all([q.refetch(), pendingQ.refetch()])
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
      pendingKeys.length > 0
        ? jsxs('div', {
            className: 'mt-1.5 flex flex-wrap gap-1',
            children: [
              jsx('span', { className: 'w-full text-[0.6875rem] text-(--ui-text-tertiary)', children: t('pendingHint') }),
              ...pendingKeys.map(item =>
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
                }, item.name)
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

function StatusBody(ctx) {
  const t = usePluginI18n(ID)
  const cwd = useValue(host.state.cwd)
  const q = useVaultStatus(ctx)
  const vaultReady = Boolean(q.data && q.data.vault)
  const auditQ = useVaultAudit(ctx, vaultReady)
  const pendingQ = usePendingPrompts(ctx, vaultReady)
  const [sealing, setSealing] = useState(false)
  const copy = (text, label) => {
    try {
      const ok = host?.clipboard?.writeText ? host.clipboard.writeText(text) : null
      if (ok && ok.then) ok.then(() => host.notify({ kind: 'success', message: t('copied', label) }))
      else host.notify({ kind: 'info', message: t('ask', label) })
    } catch (e) {
      host.notify({ kind: 'info', message: t('ask', label) })
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
    const sealedLabel = d.working_tree_sealed ? 'sealed (0B on disk)' : 'plaintext on disk'
    const auditEntries = Array.isArray(auditQ.data?.entries) ? auditQ.data.entries : []
    const auditVerified = Boolean(auditQ.data?.success && auditQ.data?.verification?.ok)
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
            row(t('fCli'), d.cli_version || '—')
          ]
        }),
        !d.working_tree_sealed
          ? jsx('div', {
              className: 'mt-2',
              children: btn(sealing ? t('sealing') : t('bSeal'), sealNow, sealing)
            })
          : null,
        jsx(SecretEntryDrawer, { ctx, cwd, q, pendingQ }),
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
                ...auditEntries.slice(0, 5).map(e => jsx('div', {
                  className: 'truncate py-0.5 text-[0.6875rem] text-(--ui-text-secondary)',
                  children: `${e.tool || 'tool'} • ${e.decision || ''}${e.path ? ' (' + e.path + ')' : ''}`
                }, String(e.id || e.entry_hash || Math.random())))
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
        onClick: () => { haptic('tap'); q.refetch() },
        children: t('refresh')
      })
    ]
  })
}

function VaultPane(ctx) {
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
      jsx(StatusBody, { ctx }),
      jsx('div', { className: 'mt-auto pt-2 text-[0.6875rem] leading-snug text-(--ui-text-quaternary)', children: t('foot') })
    ]
  })
}

function VaultPage(ctx) {
  const t = usePluginI18n(ID)
  return jsxs('main', {
    className: 'h-full overflow-auto p-5 text-sm text-(--ui-text-primary)',
    children: [
      jsx('h1', { className: 'text-xl font-semibold', children: t('pageTitle') }),
      jsx('p', { className: 'mt-1 max-w-prose text-(--ui-text-secondary)', children: t('pageSub') }),
      jsx('div', { className: 'mt-4 max-w-md', children: jsx(StatusBody, { ctx }) })
    ]
  })
}

function VaultChip(ctx) {
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
        fVault: 'Vault', fHead: 'Head', fSealed: 'Working tree', fFiles: 'Tracked files', fOperators: 'Operators', fEpoch: 'Epoch', fCli: 'CLI',
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
