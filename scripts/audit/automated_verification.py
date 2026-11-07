#!/usr/bin/env python3
"""CipherVault Automated Security & Cryptographic Verification Harness.

Designed for Track A (Security/Pen-test) and Track B (Cryptographic Audit)
external audit teams to verify all mathematical, protocol, and privacy invariants
in a single automated command.

Usage:
    python scripts/audit/automated_verification.py [--json] [--report <path>]
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run_command(args, cwd=None, env=None):
    """Run a command and capture execution metadata."""
    start_time = time.time()
    environ = os.environ.copy()
    if env:
        environ.update(env)
    environ["NO_COLOR"] = "1"

    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environ,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(exc),
            "duration_ms": duration_ms,
        }


def check_spec_hashes(repo_root):
    """Verify SHA-256 hashes of core specification documents."""
    specs = [
        "docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md",
        "docs/CURRENT_SECURITY_GUARANTEES.md",
        "crates/snapshot/CHUNK_PROTOCOL_V2.md",
    ]
    results = []
    for spec_rel in specs:
        spec_path = repo_root / spec_rel
        if spec_path.exists():
            digest = hashlib.sha256(spec_path.read_bytes()).hexdigest()
            results.append({
                "path": spec_rel,
                "exists": True,
                "sha256": digest,
                "bytes": spec_path.stat().st_size,
            })
        else:
            results.append({
                "path": spec_rel,
                "exists": False,
                "sha256": None,
                "bytes": 0,
            })
    all_exist = all(r["exists"] for r in results)
    return {
        "name": "Specification Integrity Check",
        "passed": all_exist,
        "details": results,
    }


def run_crypto_kat_tests(repo_root):
    """Run Galois Field GF(2^8) constant-time Known Answer Tests (KAT)."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-crypto", "--test", "audit_constant_time_test"],
        cwd=repo_root,
    )
    return {
        "name": "Galois Field Constant-Time KAT (GF(2^8) Axioms & Timing)",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_crypto_core_tests(repo_root):
    """Run full cryptographic primitives test suite (Shamir, AEAD, KDF, PIV, SealedBox)."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-crypto", "--lib"],
        cwd=repo_root,
    )
    return {
        "name": "Cryptographic Primitives Invariants (Shamir 3-of-5, AEAD, KDF)",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_chunk_v2_tests(repo_root):
    """Run Chunk Protocol v2 content-defined deduplication and domain isolation tests."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-snapshot"],
        cwd=repo_root,
    )
    return {
        "name": "Chunk Protocol v2 Deduplication & Domain Isolation",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_audit_privacy_canary_tests(repo_root):
    """Run Section 20 T-901 Audit Privacy Rule & Redactor canary tests."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-redact"],
        cwd=repo_root,
    )
    return {
        "name": "Section 20 T-901 Audit Privacy Rule (Canary Gate & Redactor)",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_recovery_alert_tests(repo_root):
    """Run recovery custody and alerting unit test suite."""
    res = run_command(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests/recovery"],
        cwd=repo_root,
    )
    return {
        "name": "Recovery Custody & Zero-Dependency Alerting Dispatcher",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stderr"] if res["stderr"] else res["stdout"],
    }


def run_guardian_hook_check(repo_root):
    """Run Local Guardian deep pre-commit secret leak prevention check."""
    res = run_command(
        ["cargo", "run", "-p", "ciphervault-cli", "--bin", "ciphervault", "--", "hook", "check", "--deep", "--json"],
        cwd=repo_root,
    )
    passed = False
    details = {}
    if res["stdout"]:
        try:
            start_idx = res["stdout"].find("{")
            end_idx = res["stdout"].rfind("}")
            if start_idx != -1 and end_idx != -1:
                details = json.loads(res["stdout"][start_idx:end_idx + 1])
                passed = details.get("status") == "clean" or (details.get("violations_count") == 0)
        except Exception:
            pass

    return {
        "name": "Local Vault Guardian Deep Secret Leak Pre-commit Scan",
        "passed": passed or (res["success"] and not details.get("violations")),
        "duration_ms": res["duration_ms"],
        "details": details,
        "output_summary": res["stdout"] if res["stdout"] else res["stderr"],
    }


def run_agentic_bridge_test(repo_root):
    """Run Agentic AI In-Memory Credential Bridge test suite."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-cli", "--test", "run_injection_test"],
        cwd=repo_root,
    )
    return {
        "name": "Agentic AI In-Memory Execution Bridge & Redaction Invariant",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_kubernetes_csi_tests(repo_root):
    """Run Kubernetes CSI ephemeral zero-disk volume driver unit test suite."""
    res = run_command(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests/kubernetes"],
        cwd=repo_root,
    )
    return {
        "name": "Kubernetes CSI Ephemeral Zero-Disk In-Memory Provider",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stderr"] if res["stderr"] else res["stdout"],
    }


def run_ha_database_tests(repo_root):
    """Run High-Availability clustered database backend routing test suite."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-account", "--lib", "ha_store"],
        cwd=repo_root,
    )
    return {
        "name": "HA Clustered Database Storage & Replication Routing",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_mcp_server_tests(repo_root):
    """Run Model Context Protocol (MCP) AI coding agent bridge test suite."""
    res = run_command(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests/mcp"],
        cwd=repo_root,
    )
    return {
        "name": "Model Context Protocol (MCP) AI Coding Agent Server",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stderr"] if res["stderr"] else res["stdout"],
    }


def run_agent_guardian_tests(repo_root):
    """Run Local AI Guardian continuous runtime secret scanner test suite."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-agent", "--lib", "guardian"],
        cwd=repo_root,
    )
    return {
        "name": "Local AI Guardian Continuous Runtime Sprawl Scanner",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_predictive_healer_tests(repo_root):
    """Run Autonomous Swarm Predictive Healer durability scoring test suite."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-maintenance", "--lib", "predictive_healer"],
        cwd=repo_root,
    )
    return {
        "name": "Autonomous Swarm Predictive Healer & Telemetry Engine",
        "passed": res["success"],
        "duration_ms": res["duration_ms"],
        "output_summary": res["stdout"] if res["success"] else res["stderr"],
    }


def run_sovereign_blockchain_tests(repo_root):
    """Run Sovereign CipherChain BFT quorum and light-client Merkle test suite."""
    res = run_command(
        ["cargo", "test", "-p", "ciphervault-chain"],
        cwd=repo_root,
    )
    res_e2e = run_command(
        ["cargo", "test", "--test", "sovereign_chain_test"],
        cwd=repo_root,
    )
    passed = res["success"] and res_e2e["success"]
    return {
        "name": "Sovereign Blockchain PoA Consensus & Light Client Engine",
        "passed": passed,
        "duration_ms": res["duration_ms"] + res_e2e["duration_ms"],
        "output_summary": (res["stdout"] + "\n" + res_e2e["stdout"]) if passed else (res["stderr"] + "\n" + res_e2e["stderr"]),
    }


def generate_markdown_report(suite_results):
    """Render a GitHub-flavored Markdown report for auditors."""
    lines = [
        "# CipherVault Automated Verification & Security Audit Report",
        "",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}  ",
        f"**Overall Result:** {'🟢 ALL INVARIANTS VERIFIED (PASS)' if suite_results['overall_pass'] else '🔴 VERIFICATION FAILED'}  ",
        f"**Total Execution Time:** {suite_results['total_duration_ms']} ms  ",
        "",
        "## 1. Executive Invariant Verification Matrix",
        "",
        "| Verification Module | Target Subsystem | Status | Duration |",
        "|---|---|:---:|:---:|",
    ]

    for check in suite_results["checks"]:
        icon = "✅ PASS" if check["passed"] else "❌ FAIL"
        lines.append(f"| **{check['name']}** | `{check.get('target', 'Core')}` | {icon} | {check.get('duration_ms', 0)} ms |")

    lines.extend([
        "",
        "## 2. Cryptographic Specification Checksums",
        "",
        "| Document | Status | Size | SHA-256 Digest |",
        "|---|:---:|:---:|---|",
    ])

    for spec in suite_results["spec_hashes"]["details"]:
        status = "Present" if spec["exists"] else "Missing"
        lines.append(f"| `{spec['path']}` | {status} | {spec['bytes']} B | `{spec['sha256']}` |")

    lines.extend([
        "",
        "## 3. Detailed Check Summaries",
        "",
    ])

    for check in suite_results["checks"]:
        lines.extend([
            f"### {check['name']}",
            f"- **Status:** {'PASS' if check['passed'] else 'FAIL'}",
            f"- **Execution Time:** {check.get('duration_ms', 0)} ms",
            "```text",
            check.get("output_summary", "No detailed log captured.")[:1500],
            "```",
            "",
        ])

    lines.extend([
        "---",
        "## 4. Auditor Sign-Off Template",
        "",
        "- [ ] **Track A (Pen-Test):** Local secret boundaries, injection safety, and zero-disk execution confirmed.",
        "- [ ] **Track B (Crypto):** Galois field axioms, constant-time properties, and chunk v2 derivations verified.",
        "",
        "**Auditor Signature:** ___________________________  ",
        "**Date:** ___________________________  ",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON output to stdout")
    parser.add_argument("--report", type=Path, help="Write markdown report to path")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]

    start_total = time.time()

    spec_res = check_spec_hashes(repo_root)

    checks = [
        {"target": "ciphervault-crypto", **run_crypto_kat_tests(repo_root)},
        {"target": "ciphervault-crypto", **run_crypto_core_tests(repo_root)},
        {"target": "ciphervault-snapshot", **run_chunk_v2_tests(repo_root)},
        {"target": "ciphervault-redact", **run_audit_privacy_canary_tests(repo_root)},
        {"target": "scripts/recovery", **run_recovery_alert_tests(repo_root)},
        {"target": "deploy/kubernetes", **run_kubernetes_csi_tests(repo_root)},
        {"target": "ciphervault-account", **run_ha_database_tests(repo_root)},
        {"target": "services/mcp", **run_mcp_server_tests(repo_root)},
        {"target": "ciphervault-agent", **run_agent_guardian_tests(repo_root)},
        {"target": "ciphervault-maintenance", **run_predictive_healer_tests(repo_root)},
        {"target": "ciphervault-chain", **run_sovereign_blockchain_tests(repo_root)},
        {"target": "ciphervault-cli", **run_guardian_hook_check(repo_root)},
        {"target": "ciphervault-cli", **run_agentic_bridge_test(repo_root)},
    ]

    total_duration_ms = int((time.time() - start_total) * 1000)
    overall_pass = spec_res["passed"] and all(c["passed"] for c in checks)

    suite_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "overall_pass": overall_pass,
        "total_duration_ms": total_duration_ms,
        "spec_hashes": spec_res,
        "checks": checks,
    }

    if args.report:
        report_text = generate_markdown_report(suite_results)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report_text, encoding="utf-8")
        if not args.json:
            print(f"Audit verification report saved to: {args.report}")

    if args.json:
        print(json.dumps(suite_results, indent=2))
    else:
        print("=" * 80)
        print(" CIPHERVAULT AUTOMATED SECURITY & CRYPTOGRAPHIC VERIFICATION MATRIX")
        print("=" * 80)
        for check in checks:
            mark = "[PASS]" if check["passed"] else "[FAIL]"
            print(f" {mark} {check['name']} ({check.get('duration_ms', 0)} ms)")
        print("-" * 80)
        print(f" Specifications Integrity: {'PASS' if spec_res['passed'] else 'FAIL'}")
        print(f" Overall Verification:      {'PASS' if overall_pass else 'FAIL'} (in {total_duration_ms} ms)")
        print("=" * 80)

    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    main()
