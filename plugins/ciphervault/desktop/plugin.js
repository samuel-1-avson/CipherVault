/**
 * CipherVault desktop plugin — vault health pane + statusbar chip.
 * SDK-only imports; no backend calls (pane is informational + copy actions).
 * Folder name must equal id: desktop-plugins/ciphervault/plugin.js
 * or unified: plugins/ciphervault/desktop/plugin.js
 */
import { cn, haptic, host, Tip, usePluginI18n, useValue } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'ciphervault'

function VaultPane() {
  const t = usePluginI18n(ID)
  const cwd = useValue(host.state.cwd)

  const copy = (text, label) => {
    try {
      const ok = host?.clipboard?.writeText
        ? host.clipboard.writeText(text)
        : null
      if (ok && ok.then) ok.then(() => host.notify({ kind: 'success', message: t('copied', label) }))
      else host.notify({ kind: 'info', message: t('ask', label) })
    } catch (e) {
      host.notify({ kind: 'info', message: t('ask', label) })
    }
  }

  const row = (dot, label, sub) =>
    jsxs('div', {
      className: 'flex items-start gap-2 py-1',
      children: [
        jsx('span', { className: 'mt-1 inline-block h-2 w-2 shrink-0 rounded-full ' + dot }),
        jsxs('div', {
          className: 'min-w-0',
          children: [
            jsx('div', { className: 'text-xs font-medium text-(--ui-text-primary)', children: label }),
            sub ? jsx('div', { className: 'text-[0.6875rem] leading-snug text-(--ui-text-tertiary)', children: sub }) : null
          ]
        })
      ]
    })

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

  return jsxs('div', {
    className: 'flex h-full flex-col gap-2 overflow-y-auto p-3 text-sm',
    children: [
      jsx('div', { className: 'text-xs font-semibold uppercase tracking-wide text-(--ui-text-tertiary)', children: t('paneTitle') }),
      jsx('div', {
        className: 'rounded-lg border border-(--ui-stroke-secondary) p-2',
        children: t('cwd', String(cwd || '—'))
      }),
      row('bg-emerald-400', t('s1'), t('s1sub')),
      row('bg-cyan-400', t('s2'), t('s2sub')),
      row('bg-amber-400', t('s3'), t('s3sub')),
      row('bg-rose-400', t('s4'), t('s4sub')),
      jsxs('div', {
        className: 'mt-1 flex flex-wrap gap-1.5',
        children: [
          btn(t('bScan'), () => copy('Scan my workspace for secret sprawl with ciphervault_scan (masked, autofix .gitignore).', 'scan')),
          btn(t('bStatus'), () => copy('Show CipherVault tracked files and snapshot head with ciphervault_status (keys only).', 'status')),
          btn(t('bRun'), () => copy('Run my dev command with secrets in RAM via ciphervault_run, scrubbed output.', 'run')),
          btn(t('bDrill'), () => copy('Prove my recovery kit works with ciphervault_recovery_drill using my kit FILE PATH (I will never paste its contents).', 'drill'))
        ]
      }),
      jsx('div', { className: 'mt-auto pt-2 text-[0.6875rem] leading-snug text-(--ui-text-quaternary)', children: t('foot') })
    ]
  })
}

function VaultChip() {
  const t = usePluginI18n(ID)
  return jsx(Tip, {
    label: t('chipTip'),
    children: jsx('button', {
      type: 'button',
      className: cn(
        'inline-flex h-full items-center gap-1 px-1.5 text-[0.6875rem] transition-colors',
        'text-(--ui-text-tertiary) hover:bg-(--chrome-action-hover) hover:text-foreground'
      ),
      onClick: () => {
        haptic('tap')
        host.notify({ kind: 'info', message: t('chipMsg') })
      },
      children: 'cv • vault'
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
        cwd: c => `workspace: ${c}`,
        s1: 'Scan before you commit',
        s1sub: 'ciphervault_scan finds .env / keys / tokens, masked.',
        s2: 'Run without leaking',
        s2sub: 'ciphervault_run injects env in RAM, scrubs output.',
        s3: 'Snapshot after edits',
        s3sub: 'ciphervault_push seals an encrypted snapshot.',
        s4: 'Prove recovery on day one',
        s4sub: 'ciphervault_recovery_drill restores your kit into a temp dir — paths only, never contents.',
        bScan: 'Copy scan prompt',
        bStatus: 'Copy status prompt',
        bRun: 'Copy run prompt',
        bDrill: 'Copy drill prompt',
        copied: l => `Prompt copied — paste it to Hermes (${l}).`,
        ask: l => `Ask Hermes: use ciphervault tool (${l}) — clipboard unavailable.`,
        foot: 'Values never print. Operators see ciphertext only. Binary: dist/bin or $CIPHERVAULT_BIN.',
        chipTip: 'CipherVault — zero-knowledge secrets',
        chipMsg: 'Open the CipherVault pane for scan / run / push prompts.'
      }
    })

    ctx.register({
      id: 'pane',
      area: 'panes',
      title: 'ciphervault',
      data: { placement: 'right', width: '280px' },
      render: () => jsx(VaultPane, {})
    })

    ctx.register({
      id: 'chip',
      area: 'statusBar.right',
      order: 130,
      render: () => jsx(VaultChip, {})
    })

    ctx.register({
      id: 'scan-cmd',
      area: 'commandPalette',
      data: {
        command: 'ciphervault.scan',
        title: 'CipherVault: scan for secret sprawl'
      },
      render: () => null
    })
  }
}
