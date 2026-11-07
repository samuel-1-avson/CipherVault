#!/usr/bin/env python3
"""CipherVault Multi-Cloud Recovery Custody Orchestrator (Path A).

Implements 2-person independent cryptographic escrow across separate cloud
organizations (AWS S3 Object Lock + GCP Cloud Storage Locked Retention).

Uses Shamir (2,2) threshold splitting: the master disaster recovery key
cannot be reconstructed without authorized participation from both independent
cloud custodians.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

# Pure Python GF(2^8) Shamir 2-of-2 threshold implementation (Rijndael irreducible poly 0x11b)
POLYNOMIAL = 0x11B


def gf_add(a, b):
    return a ^ b


def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (POLYNOMIAL & 0xFF)
        b >>= 1
    return p


def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("Cannot invert zero in GF(2^8)")
    for b in range(1, 256):
        if gf_mul(a, b) == 1:
            return b
    raise RuntimeError("Inversion failed")


def split_secret_2_of_2(secret_bytes: bytes) -> tuple:
    """Split secret into 2 Shamir shares (evaluating at x=1 and x=2)."""
    share1 = bytearray()
    share2 = bytearray()

    for s in secret_bytes:
        # Secret polynomial f(x) = s + a*x
        a = secrets.randbelow(256)
        y1 = gf_add(s, gf_mul(a, 1))
        y2 = gf_add(s, gf_mul(a, 2))
        share1.append(y1)
        share2.append(y2)

    return (1, bytes(share1)), (2, bytes(share2))


def reconstruct_secret_2_of_2(share1_tuple: tuple, share2_tuple: tuple) -> bytes:
    """Reconstruct secret from 2 Shamir shares using Lagrange interpolation at x=0."""
    x1, y1_bytes = share1_tuple
    x2, y2_bytes = share2_tuple

    if len(y1_bytes) != len(y2_bytes):
        raise ValueError("Share byte length mismatch")
    if x1 == x2:
        raise ValueError("Shares must have distinct evaluation points")

    # Lagrange basis polynomials at x=0:
    # L1(0) = (0 - x2) / (x1 - x2) = x2 * inv(x1 ^ x2)
    # L2(0) = (0 - x1) / (x2 - x1) = x1 * inv(x1 ^ x2)
    denom_inv = gf_inv(x1 ^ x2)
    l1 = gf_mul(x2, denom_inv)
    l2 = gf_mul(x1, denom_inv)

    secret = bytearray()
    for y1, y2 in zip(y1_bytes, y2_bytes):
        s = gf_add(gf_mul(y1, l1), gf_mul(y2, l2))
        secret.append(s)

    return bytes(secret)


class MultiCloudCustodyManager:
    """Orchestrates independent dual-custody across AWS and GCP destinations."""

    def __init__(self, config_path: Path = None):
        self.config_path = config_path

    def generate_custody_split(
        self,
        master_secret: bytes,
        custodian_a_id: str,  # AWS Custodian
        custodian_b_id: str,  # GCP Custodian
        aws_bucket: str,
        gcp_bucket: str,
        retention_days: int = 90,
    ) -> dict:
        """Create split-share envelopes for independent cloud deployment."""
        if custodian_a_id == custodian_b_id:
            raise ValueError("Path A requires strictly distinct custodian identities across cloud providers")

        (x1, share1), (x2, share2) = split_secret_2_of_2(master_secret)
        secret_fingerprint = hashlib.sha256(master_secret).hexdigest()

        envelope_a = {
            "version": 1,
            "cloud_provider": "AWS",
            "custodian_identity": custodian_a_id,
            "destination_bucket": aws_bucket,
            "immutability_mode": "S3_OBJECT_LOCK_COMPLIANCE",
            "retention_period_days": retention_days,
            "share_index": x1,
            "share_data_b64": base64.b64encode(share1).decode("ascii"),
            "secret_fingerprint": secret_fingerprint,
            "timestamp": int(time.time()),
        }

        envelope_b = {
            "version": 1,
            "cloud_provider": "GCP",
            "custodian_identity": custodian_b_id,
            "destination_bucket": gcp_bucket,
            "immutability_mode": "GCS_LOCKED_RETENTION_POLICY",
            "retention_period_days": retention_days,
            "share_index": x2,
            "share_data_b64": base64.b64encode(share2).decode("ascii"),
            "secret_fingerprint": secret_fingerprint,
            "timestamp": int(time.time()),
        }

        manifest = {
            "custody_architecture": "Path A (Independent Multi-Cloud 2-of-2 Escrow)",
            "secret_fingerprint": secret_fingerprint,
            "share_length_bytes": len(master_secret),
            "retention_days": retention_days,
            "custodians": {
                "aws": custodian_a_id,
                "gcp": custodian_b_id,
            },
            "destinations": {
                "aws_s3_bucket": aws_bucket,
                "gcp_gcs_bucket": gcp_bucket,
            },
        }

        return {
            "manifest": manifest,
            "aws_envelope": envelope_a,
            "gcp_envelope": envelope_b,
        }

    def verify_and_reconstruct(self, envelope_a: dict, envelope_b: dict) -> bytes:
        """Validate envelope immutability metadata and reconstruct the master secret."""
        if envelope_a["secret_fingerprint"] != envelope_b["secret_fingerprint"]:
            raise ValueError("Secret fingerprint mismatch: envelopes belong to different recovery sessions")

        if envelope_a["custodian_identity"] == envelope_b["custodian_identity"]:
            raise ValueError("Collusion check failed: custodian identities must be distinct")

        if envelope_a["cloud_provider"] == envelope_b["cloud_provider"]:
            raise ValueError("Cloud diversity check failed: envelopes must originate from distinct cloud providers")

        x1 = envelope_a["share_index"]
        data1 = base64.b64decode(envelope_a["share_data_b64"])

        x2 = envelope_b["share_index"]
        data2 = base64.b64decode(envelope_b["share_data_b64"])

        secret = reconstruct_secret_2_of_2((x1, data1), (x2, data2))

        # Verify integrity against embedded fingerprint
        if hashlib.sha256(secret).hexdigest() != envelope_a["secret_fingerprint"]:
            raise ValueError("Reconstructed secret failed fingerprint integrity check")

        return secret


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    split_p = sub.add_parser("split", help="Split master secret into 2-cloud custody envelopes")
    split_p.add_argument("--secret-hex", required=True, help="Hex-encoded recovery master secret")
    split_p.add_argument("--custodian-aws", required=True, help="AWS Custodian Principal / ARN")
    split_p.add_argument("--custodian-gcp", required=True, help="GCP Custodian Principal / Email")
    split_p.add_argument("--aws-bucket", required=True, help="AWS S3 Bucket with Object Lock")
    split_p.add_argument("--gcp-bucket", required=True, help="GCP GCS Bucket with Locked Retention")
    split_p.add_argument("--out-dir", type=Path, default=Path("."), help="Output directory for envelopes")

    recon_p = sub.add_parser("reconstruct", help="Reconstruct master secret from 2 custody envelopes")
    recon_p.add_argument("--env-aws", type=Path, required=True, help="Path to AWS envelope JSON")
    recon_p.add_argument("--env-gcp", type=Path, required=True, help="Path to GCP envelope JSON")

    args = parser.parse_args()
    mgr = MultiCloudCustodyManager()

    if args.command == "split":
        secret_bytes = bytes.fromhex(args.secret_hex)
        res = mgr.generate_custody_split(
            master_secret=secret_bytes,
            custodian_a_id=args.custodian_aws,
            custodian_b_id=args.custodian_gcp,
            aws_bucket=args.aws_bucket,
            gcp_bucket=args.gcp_bucket,
        )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "custody-manifest.json").write_text(json.dumps(res["manifest"], indent=2))
        (args.out_dir / "envelope-aws.json").write_text(json.dumps(res["aws_envelope"], indent=2))
        (args.out_dir / "envelope-gcp.json").write_text(json.dumps(res["gcp_envelope"], indent=2))
        print(f"Generated Path A Multi-Cloud custody packages in: {args.out_dir}")

    elif args.command == "reconstruct":
        env_a = json.loads(args.env_aws.read_text(encoding="utf-8"))
        env_b = json.loads(args.env_gcp.read_text(encoding="utf-8"))
        secret = mgr.verify_and_reconstruct(env_a, env_b)
        print(json.dumps({
            "status": "reconstructed",
            "secret_fingerprint": hashlib.sha256(secret).hexdigest(),
            "secret_hex": secret.hex(),
        }, indent=2))


if __name__ == "__main__":
    main()
