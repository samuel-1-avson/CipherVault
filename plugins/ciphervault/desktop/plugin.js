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

function StatusBody(ctx) {
  const t = usePluginI18n(ID)
  const q = useVaultStatus(ctx)
  const copy = (text, label) => {
    try {
      const ok = host?.clipboard?.writeText ? host.clipboard.writeText(text) : null
      if (ok && ok.then) ok.then(() => host.notify({ kind: 'success', message: t('copied', label) }))
      else host.notify({ kind: 'info', message: t('ask', label) })
    } catch (e) {
      host.notify({ kind: 'info', message: t('ask', label) })
    }
  }
  const btn = (label, onClick) =>
    jsx('button', {
      type: 'button',
      className: cn(
        'rounded-md border border-(--ui-stroke-secondary) px-2 py-1 text-[0.6875rem]',
        'text-(--ui-text-secondary) hover:bg-(--chrome-action-hover) hover:text-foreground'
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
    state = jsxs('div', {
      children: [
        jsxs('div', {
          className: 'rounded-lg border border-(--ui-stroke-secondary) p-2',
          children: [
            row(t('fVault'), d.vault_id_short || '—'),
            row(t('fHead'), d.active_head_short || t('none')),
            row(t('fFiles'), d.tracked_files ?? paths.length),
            row(t('fOperators'), d.operators ?? 0),
            row(t('fEpoch'), d.current_epoch ?? '—'),
            row(t('fCli'), d.cli_version || '—')
          ]
        }),
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
  const color = q.isLoading ? 'bg-zinc-400' : ok ? 'bg-emerald-400' : 'bg-amber-400'
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
        noBinarySub: 'Run `hermes ciphervault bootstrap` in a terminal (Windows), or set CIPHERVAULT_BIN.',
        noVault: 'No vault in this workspace',
        noVaultSub: 'Run `ciphervault init` here, then `ciphervault track .env` and `ciphervault push --local`.',
        fVault: 'Vault', fHead: 'Head', fFiles: 'Tracked files', fOperators: 'Operators', fEpoch: 'Epoch', fCli: 'CLI',
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
        foot: 'Values never print. Operators see ciphertext only. Binary via bootstrap, $CIPHERVAULT_BIN, or PATH.',
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
