# CipherVault Hermes plugin

Zero-knowledge secret backup, native inside Hermes. Four tools, zero plaintext in context:

| Tool | Does |
|---|---|
| `ciphervault_scan` | masked sprawl scan (workspace + staged diffs), optional `.gitignore` fix |
| `ciphervault_status` | tracked files + snapshot head, keys only |
| `ciphervault_run` | run any command with env in RAM, scrubbed output |
| `ciphervault_push` | encrypted snapshot after edits |

## Install (dev)

```bash
# from a CipherVault checkout (prebuilt binary in dist/bin)
hermes plugins install ./plugins/ciphervault --no-enable
hermes plugins enable ciphervault
# restart Hermes — tools appear as ciphervault_*
```

Binary resolution: `$CIPHERVAULT_BIN` → `dist/bin/ciphervault[.exe]` → `target/{debug,release}` → `PATH`.

## Validate (same check catalog CI runs)

```bash
hermes plugins validate ./plugins/ciphervault --install-deps
hermes plugins doctor ciphervault
```

## 90-second demo script

1. `ciphervault_status` → keys only, no values.
2. `ciphervault_run` with `["npm","test"]` → green run, values show `***redacted***`.
3. Stage a stray `.env` → `ciphervault_scan` flags it → `--fix` gitignores it.
4. `ciphervault_push -m "rotate db creds"` → encrypted snapshot sealed.

Desktop pane (`desktop/plugin.js`): vault checklist + one-click prompt copy + `cv • vault` statusbar chip.
