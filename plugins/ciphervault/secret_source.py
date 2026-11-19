"""Hermes bulk secret source backed by `ciphervault export-env`."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from . import _runtime, binary


def _make_secret_source():
    from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

    class CipherVaultSecretSource(SecretSource):
        """Bulk source: contributes every var of a vault's latest
        snapshot (or one tracked file) as Hermes env vars. Values go
        from the CLI straight into FetchResult — never logged here."""

        name = "ciphervault"
        label = "CipherVault"
        shape = "bulk"
        scheme = "ciphervault"

        def fetch(self, cfg, home_path):
            result = FetchResult()
            try:
                cfg = cfg if isinstance(cfg, dict) else {}
                vault_path = cfg.get("vault_path") or os.getcwd()
                bin_path, _src = _runtime.resolve(binary, "find_binary")()
                if not bin_path:
                    result.error = "ciphervault binary not found. " + binary._COMPATIBLE_CLI_HINT
                    result.error_kind = ErrorKind.BINARY_MISSING
                    return result
                argv = [bin_path, "export-env"]
                if cfg.get("env_file"):
                    argv += ["--env-file", str(cfg["env_file"])]
                if cfg.get("allow_working_copy"):
                    argv.append("--allow-working-copy")
                env = binary._minimal_env()
                try:
                    proc = subprocess.run(
                        argv,
                        cwd=str(vault_path),
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=60,
                        stdin=subprocess.DEVNULL,
                        env=env,
                    )
                except subprocess.TimeoutExpired:
                    result.error = "ciphervault export-env timed out after 60s"
                    result.error_kind = ErrorKind.TIMEOUT
                    return result
                except OSError as exc:
                    result.error = f"could not run ciphervault: {exc}"
                    result.error_kind = ErrorKind.BINARY_MISSING
                    return result
                if proc.returncode != 0:
                    result.error = f"ciphervault export-env exited {proc.returncode}: {(proc.stderr or '')[:200]}"
                    result.error_kind = ErrorKind.AUTH_FAILED
                    return result
                try:
                    values = json.loads(proc.stdout or "{}")
                except Exception:
                    result.error = "ciphervault export-env returned non-JSON output"
                    result.error_kind = ErrorKind.INTERNAL
                    return result
                if isinstance(values, dict):
                    result.secrets = {str(k): str(v) for k, v in values.items()}
                result.binary_path = Path(bin_path)
                return result
            except Exception as exc:  # fetch() must never raise
                result.error = str(exc)
                result.error_kind = ErrorKind.INTERNAL
                return result

        def config_schema(self):
            return {
                "vault_path": {
                    "type": "str",
                    "default": "",
                    "description": "Directory containing the vault (where .ciphervault/ lives)",
                },
                "env_file": {
                    "type": "str",
                    "default": "",
                    "description": "Optional single tracked secret file to export",
                },
                "allow_working_copy": {
                    "type": "bool",
                    "default": False,
                    "description": "Export from working files instead of the latest snapshot",
                },
            }

        def remediation(self, kind, cfg):
            return (
                binary._COMPATIBLE_CLI_HINT
                + " Then run `ciphervault init` in your project (or set secrets.ciphervault.vault_path)."
            )

    return CipherVaultSecretSource()
