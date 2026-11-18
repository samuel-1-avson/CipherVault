"""Slash command (`/ciphervault`), terminal CLI (`hermes ciphervault`), quickstart, and workspace setup."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import _runtime, binary, bridge

_self = sys.modules[__name__]

_STARTER_POLICY_TOML = """\
[vault]
sealed_mode = {sealed_mode}
default_no_net = true

[profiles.test]
description = "Offline test suite (injects matching DB/Redis/TEST_* keys)"
commands = ["pytest", "python", "npm", "npx", "node", "cargo", "vitest"]
allow_keys = ["DATABASE_URL", "REDIS_URL", "TEST_*"]
no_net = true

[profiles.llm_eval]
description = "LLM evaluation via loopback credential proxy (injects configured provider keys)"
commands = ["python", "node"]
allow_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]
proxy = true
"""


def _parse_slash_run_args(tokens: list[str]) -> tuple[dict | None, str | None]:
    """Parse `/ciphervault run [--profile P] [--dry-run] [--proxy] [--no-net] [--allow-keys K1,K2] [--] <cmd...>`."""
    params: dict = {}
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            idx += 1
            break
        if tok == "--profile":
            if idx + 1 >= len(tokens):
                return None, "Usage: /ciphervault run [--profile <name>] [--dry-run] [--proxy] [--no-net] [--allow-keys K1,K2] [--] <command> [args...]"
            params["profile"] = tokens[idx + 1]
            idx += 2
            continue
        if tok.startswith("--profile="):
            params["profile"] = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--allow-keys":
            if idx + 1 >= len(tokens):
                return None, "--allow-keys requires a comma-separated list of variable names or patterns"
            params["allow_keys"] = [k.strip() for k in tokens[idx + 1].split(",") if k.strip()]
            idx += 2
            continue
        if tok.startswith("--allow-keys="):
            rhs = tok.split("=", 1)[1]
            params["allow_keys"] = [k.strip() for k in rhs.split(",") if k.strip()]
            idx += 1
            continue
        if tok == "--dry-run":
            params["dry_run"] = True
            idx += 1
            continue
        if tok == "--proxy":
            params["proxy"] = True
            idx += 1
            continue
        if tok == "--no-net":
            params["no_net"] = True
            idx += 1
            continue
        if tok == "--env-file":
            if idx + 1 >= len(tokens):
                return None, "--env-file requires a path"
            params["env_file"] = tokens[idx + 1]
            idx += 2
            continue
        if tok.startswith("--env-file="):
            params["env_file"] = tok.split("=", 1)[1]
            idx += 1
            continue
        break
    cmd = tokens[idx:]
    if not cmd:
        return None, "Usage: /ciphervault run [--profile <name>] [--dry-run] [--proxy] [--no-net] [--allow-keys K1,K2] [--] <command> [args...]"
    params["command"] = cmd
    return params, None


def _parse_slash_drill_args(tokens: list[str]) -> tuple[dict | None, str | None]:
    """Parse `/ciphervault drill <kit_path> | --kit <path> | --shares <p1> [p2...] [--via <url>...]`."""
    kit = None
    shares: list[str] = []
    via: list[str] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--kit":
            if idx + 1 >= len(tokens):
                return None, "--kit requires a recovery kit file path"
            kit = tokens[idx + 1]
            idx += 2
            continue
        if tok.startswith("--kit="):
            kit = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--shares":
            idx += 1
            while idx < len(tokens) and not tokens[idx].startswith("--"):
                shares.append(tokens[idx])
                idx += 1
            continue
        if tok == "--via":
            idx += 1
            while idx < len(tokens) and not tokens[idx].startswith("--"):
                via.append(tokens[idx])
                idx += 1
            continue
        if not tok.startswith("-") and kit is None:
            kit = tok
            idx += 1
            continue
        return None, f"Unrecognized option for /ciphervault drill: {tok!r}"
    if not kit and not shares:
        return None, "Usage: /ciphervault drill <kit_path> | --kit <path> | --shares <p1> [p2...] [--via <url>...]"
    params: dict = {}
    if kit:
        params["kit"] = kit
    if shares:
        params["shares"] = shares
    if via:
        params["via"] = via
    return params, None


def _slash_ciphervault(raw_args, **kwargs):
    raw_str = (raw_args or "").strip()
    try:
        parts = shlex.split(raw_str) if raw_str else []
    except ValueError:
        parts = raw_str.split()
    sub = parts[0].lower() if parts else "status"
    rest = parts[1:]

    if sub in ("setup", "bootstrap"):
        return json.dumps(_runtime.resolve(binary, "bootstrap_binary")(), indent=2)
    if sub == "version":
        bin_path, source = _runtime.resolve(binary, "find_binary")()
        return (
            f"plugin v{_runtime.PLUGIN_VERSION} (target CLI v{binary.RELEASE_VERSION}); "
            f"binary: {bin_path or 'missing'} ({source})"
        )

    tool_for = {
        "status": "ciphervault_status",
        "scan": "ciphervault_scan",
        "drill": "ciphervault_recovery_drill",
        "push": "ciphervault_push",
        "run": "ciphervault_run",
        "redact": "ciphervault_redact",
        "doctor": "ciphervault_env_doctor",
        "diff": "ciphervault_diff",
    }
    if sub in tool_for:
        params: dict = {}
        if sub == "run":
            parsed, err = _parse_slash_run_args(rest)
            if err:
                return err
            params = parsed
        elif sub == "redact":
            text = re.sub(r"^\s*redact\b\s*", "", raw_args or "", count=1, flags=re.IGNORECASE)
            if not text:
                return "Usage: /ciphervault redact <text>"
            params = {"text": text}
        elif sub == "drill":
            parsed, err = _parse_slash_drill_args(rest)
            if err:
                return err
            params = parsed
        elif sub == "push" and rest:
            params["message"] = " ".join(rest)
        elif sub == "diff" and rest:
            params["snapshot_a"] = rest[0]
            if len(rest) > 1:
                params["snapshot_b"] = rest[1]
        elif sub == "scan" and rest:
            if "--fix" in rest:
                params["fix"] = True
            if "--no-deep" in rest:
                params["deep"] = False
        elif sub == "doctor" and rest:
            if "--sync-env-example" in rest:
                params["sync_env_example"] = True
        try:
            return _runtime._ctx["ctx"].dispatch_tool(tool_for[sub], params)
        except Exception as exc:
            return f"ciphervault {sub} failed: {exc}"

    return (
        "Usage: /ciphervault <status|scan|run|push|drill|redact|doctor|diff|version|setup>\n"
        "Tools: ciphervault_status, ciphervault_scan, ciphervault_run, "
        "ciphervault_push, ciphervault_recovery_drill, ciphervault_redact, "
        "ciphervault_env_doctor, ciphervault_secret_generate, ciphervault_secret_prompt, "
        "ciphervault_diff, ciphervault_proxy_doctor, ciphervault_audit."
    )


def _qs_run(bin_path, args, cwd):
    proc = subprocess.run(
        [bin_path, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        env=binary._minimal_env(),
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def quickstart(progress=print, keep=False):
    """Two-minute guided demo: throwaway vault, fake secrets, sealed
    snapshot, RAM-only run dry-run, audit verify — then cleanup."""
    bin_path, _src = _runtime.resolve(binary, "find_binary")()
    if not bin_path:
        result = _runtime.resolve(binary, "bootstrap_binary")(progress=progress)
        if not result.get("success"):
            return result
        bin_path = result["binary"]
    demo = Path(tempfile.mkdtemp(prefix="cv-quickstart-"))
    try:
        (demo / ".env").write_text(
            "DEMO_API_KEY=sk-demo-0000000000000000000000000000fake\n"
            "DEMO_DB_URL=postgres://demo:demo-password-fake@localhost:5432/demo\n",
            encoding="utf-8",
        )
        steps = [
            (
                "1/5  Create a throwaway vault (kit saved inside the demo dir)",
                ["init", "--save-kit", str(demo / "recovery-kit.txt")],
            ),
            ("2/5  Track the fake .env (it is git-ignored automatically)", ["track", ".env"]),
            ("3/5  Seal an encrypted snapshot (local only)", ["push", "--local", "-m", "quickstart demo"]),
            ("4/5  RAM-only run, dry-run: names only, values never printed", ["run", "--dry-run", "--", "echo", "demo"]),
            ("5/5  Verify the tamper-evident audit chain", ["agent-log", "verify"]),
        ]
        qs_run_fn = _runtime.resolve(_self, "_qs_run")
        for label, args in steps:
            progress(f"\n== {label}\n$ ciphervault {' '.join(args)}")
            rc, out = qs_run_fn(bin_path, args, str(demo))
            progress(out.strip()[-1200:] or "(no output)")
            if rc != 0:
                return {
                    "success": False,
                    "error": f"step failed ({args[0]}): rc={rc}",
                    "demo_dir": str(demo),
                }
        progress(
            "\nThat's the loop: sealed snapshots, RAM-only injection, and an\n"
            "audit chain that proves what an agent touched. Real vault next:\n"
            "  cd your-project && ciphervault init && ciphervault track .env"
        )
        return {"success": True, "demo_dir": str(demo) if keep else None}
    finally:
        if not keep:
            shutil.rmtree(demo, ignore_errors=True)


def _upsert_hermes_secret_source(config_path: Path, vault_path: str) -> dict:
    """Safely enable `secrets.ciphervault` in `$HERMES_HOME/config.yaml`
    without touching or logging any secret values."""
    existing = ""
    if config_path.is_file():
        existing = config_path.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(existing) if existing.strip() else {}
        if not isinstance(data, dict):
            return {"updated": False, "error": f"{config_path} is not a YAML mapping"}
        secrets_cfg = data.setdefault("secrets", {})
        if not isinstance(secrets_cfg, dict):
            return {"updated": False, "error": "config.yaml `secrets` section is not a mapping"}
        secrets_cfg["ciphervault"] = {
            "enabled": True,
            "vault_path": str(vault_path),
            "allow_working_copy": False,
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return {"updated": True, "path": str(config_path), "vault_path": str(vault_path)}
    except ImportError:
        if "ciphervault:" in existing:
            return {"updated": False, "already_configured": True, "path": str(config_path)}
        snippet = (
            "\nsecrets:\n"
            "  ciphervault:\n"
            "    enabled: true\n"
            f"    vault_path: {json.dumps(str(vault_path))}\n"
            "    allow_working_copy: false\n"
        )
        if re.search(r"(?m)^secrets:\s*$", existing):
            updated = re.sub(
                r"(?m)^secrets:\s*$",
                "secrets:\n  ciphervault:\n    enabled: true\n"
                f"    vault_path: {json.dumps(str(vault_path))}\n"
                "    allow_working_copy: false",
                existing,
                count=1,
            )
        else:
            updated = existing + snippet
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(updated, encoding="utf-8")
        return {"updated": True, "path": str(config_path), "vault_path": str(vault_path)}


def setup_workspace(
    cwd=None,
    sealed=True,
    bootstrap=True,
    wire_hermes_config=False,
    force=False,
    dry_run=False,
    progress=print,
):
    """One-command setup wizard: verify/bootstrap binary, scaffold
    `.ciphervault/policy.toml` inside an initialized vault, and optionally
    wire `secrets.ciphervault` in `$HERMES_HOME/config.yaml`."""
    target_dir = Path(cwd or os.getcwd()).resolve()
    bin_path, source = _runtime.resolve(binary, "find_binary")()
    binary_info = {"binary": bin_path, "source": source, "bootstrapped": False}
    if not bin_path:
        if bootstrap and not dry_run:
            boot = _runtime.resolve(binary, "bootstrap_binary")(progress=progress)
            if not boot.get("success"):
                return {
                    "success": False,
                    "step": "bootstrap",
                    "error": boot.get("error", "binary bootstrap failed"),
                    "binary": binary_info,
                }
            bin_path = boot.get("binary")
            binary_info = {"binary": bin_path, "source": "bootstrapped", "bootstrapped": True}
        elif bootstrap and dry_run:
            binary_info["action"] = "would_bootstrap"
        else:
            return {
                "success": False,
                "step": "binary",
                "error": "ciphervault binary not found (run without --no-bootstrap or set CIPHERVAULT_BIN)",
                "binary": binary_info,
            }

    vault_root = _runtime.resolve(bridge, "_vault_root")(str(target_dir))
    policy_info = {"written": False, "path": None}
    next_steps = []

    if vault_root is None:
        next_steps.append(
            f"Initialize a vault in your terminal: cd {target_dir} && ciphervault init && ciphervault track .env && ciphervault push --local --shred"
        )
    else:
        policy_path = Path(vault_root) / ".ciphervault" / "policy.toml"
        policy_info["path"] = str(policy_path)
        if policy_path.exists() and not force:
            policy_info["already_exists"] = True
        elif dry_run:
            policy_info["action"] = "would_write"
        else:
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(
                _STARTER_POLICY_TOML.format(sealed_mode="true" if sealed else "false"),
                encoding="utf-8",
            )
            policy_info["written"] = True

    hermes_cfg_path = binary._hermes_home() / "config.yaml"
    hermes_info = {"path": str(hermes_cfg_path), "updated": False}
    if wire_hermes_config:
        vault_ref = str(vault_root or target_dir)
        if dry_run:
            hermes_info["action"] = "would_wire_secret_source"
            hermes_info["vault_path"] = vault_ref
        else:
            hermes_info = _upsert_hermes_secret_source(hermes_cfg_path, vault_ref)
            if hermes_info.get("error"):
                return {
                    "success": False,
                    "step": "wire_hermes",
                    "error": hermes_info["error"],
                    "binary": binary_info,
                    "policy": policy_info,
                    "hermes_secret_source": hermes_info,
                }
    else:
        next_steps.append(
            "Optional: re-run with `--wire-hermes` to configure Hermes's own `secrets.ciphervault` source."
        )

    return {
        "success": True,
        "dry_run": bool(dry_run),
        "cwd": str(target_dir),
        "vault_initialized": vault_root is not None,
        "vault_root": str(vault_root) if vault_root is not None else None,
        "binary": binary_info,
        "policy": policy_info,
        "hermes_secret_source": hermes_info,
        "next_steps": next_steps,
    }


def _cli_setup(parser):
    sp = parser.add_subparsers(dest="ciphervault_cmd")
    sp.add_parser("bootstrap", help="Download + verify the pinned CipherVault binary")
    sp.add_parser("status", help="Binary resolution + vault status for the cwd")
    sp.add_parser("doctor", help="Check binary, vault, and wiring")
    qs = sp.add_parser("quickstart", help="Two-minute guided demo in a throwaway vault")
    qs.add_argument("--keep", action="store_true", help="Keep the demo directory")
    su = sp.add_parser("setup", help="Setup wizard: binary + .ciphervault/policy.toml + Hermes secret source")
    su.add_argument("--cwd", default=None, help="Target workspace directory (default: current directory)")
    su.add_argument("--no-bootstrap", action="store_true", help="Do not download binary if missing")
    su.add_argument("--unsealed", action="store_true", help="Set sealed_mode = false in starter policy.toml")
    su.add_argument("--wire-hermes", action="store_true", help="Enable secrets.ciphervault in $HERMES_HOME/config.yaml")
    su.add_argument("--force", action="store_true", help="Overwrite existing .ciphervault/policy.toml")
    su.add_argument("--dry-run", action="store_true", help="Show planned setup actions without writing files")


def _cli_handler(args):
    cmd = getattr(args, "ciphervault_cmd", None) or "status"
    if cmd == "bootstrap":
        result = _runtime.resolve(binary, "bootstrap_binary")()
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "setup":
        result = setup_workspace(
            cwd=getattr(args, "cwd", None),
            sealed=not bool(getattr(args, "unsealed", False)),
            bootstrap=not bool(getattr(args, "no_bootstrap", False)),
            wire_hermes_config=bool(getattr(args, "wire_hermes", False)),
            force=bool(getattr(args, "force", False)),
            dry_run=bool(getattr(args, "dry_run", False)),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "quickstart":
        result = quickstart(keep=bool(getattr(args, "keep", False)))
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    if cmd == "doctor":
        result = binary.binary_diagnostics(os.getcwd())
        status = _runtime.resolve(bridge, "_run_cli_json")(["status", "--json"], os.getcwd())
        result["status"] = status
        result["success"] = bool(result["success"] and status.get("success"))
        print(json.dumps(result, indent=2))
        return 0 if result["success"] else 1
    bin_path, source = _runtime.resolve(binary, "find_binary")()
    print(f"binary: {bin_path or 'missing'} ({source})")
    result = _runtime.resolve(bridge, "_run_cli_json")(["status", "--json"], os.getcwd())
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1
