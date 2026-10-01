#!/usr/bin/env python3
"""Render an explicit custody provisioning plan. Never executes gcloud.

All human identities and billing/parent governance must be supplied explicitly.
Examples remain invalid until those actual independent owners are identified.
The final retention-lock step is separated for custodian review.
"""

import argparse
import json
from pathlib import Path
import re
import sys
import time

import account_custody as custody


def email(value):
    custody.require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value)
                    and "REPLACE" not in value.upper(), "actual custodian email identities are required")
    return value.lower()


def human_principals(values):
    custody.require(isinstance(values, list) and values, "named human custodian principals are required")
    result = set()
    for value in values:
        custody.require(isinstance(value, str) and value.startswith(("user:", "group:")),
                        "custodian principals must be actual named users or groups")
        kind, address = value.split(":", 1)
        result.add(kind + ":" + email(address))
    custody.require(len(result) == len(values), "custodian principals contain duplicates")
    return result


def project_id(value):
    custody.require(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", value), "GCP project ID is invalid")
    return value


def validate(cfg, now=None):
    fields = {"schema_version", "production_project_id", "production_project_number", "production_admin_principals",
              "recovery_project_id", "recovery_bucket_name", "bucket_location", "retention_days", "billing_account",
              "organization_id", "folder_id", "provisioner_account", "custody_admin_principals", "restore_principals",
              "offline_key_custodian_principals", "production_uploader_principal", "age_public_recipient",
              "governance_review_reference", "independence_reviewed", "review_expires_at_utc"}
    custody.require(set(cfg) == fields and cfg["schema_version"] == 1, "provisioning fields are incomplete or unknown")
    source = project_id(cfg["production_project_id"])
    target = project_id(cfg["recovery_project_id"])
    custody.require(source != target, "recovery project must differ from production")
    custody.require(isinstance(cfg["production_project_number"], str) and re.fullmatch(r"[1-9][0-9]{5,20}",
                    cfg["production_project_number"]), "production project number is required")
    production = human_principals(cfg["production_admin_principals"])
    admins = human_principals(cfg["custody_admin_principals"])
    restorers = human_principals(cfg["restore_principals"])
    keys = human_principals(cfg["offline_key_custodian_principals"])
    provisioner = "user:" + email(cfg["provisioner_account"])
    custody.require(provisioner in admins, "provisioner must be a named independent custody administrator")
    custody.require(not production.intersection(admins | restorers | keys) and not keys.intersection(admins | restorers),
                    "production, backup/restore, and offline key custodians must have distinct listed identities")
    uploader = cfg["production_uploader_principal"]
    custody.require(isinstance(uploader, str) and re.fullmatch(r"serviceAccount:[a-z][a-z0-9-]{4,28}[a-z0-9]@" +
                    re.escape(source) + r"\.iam\.gserviceaccount\.com", uploader), "uploader must be an explicit existing production workload service account")
    custody.require(isinstance(cfg["recovery_bucket_name"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]",
                    cfg["recovery_bucket_name"]), "recovery bucket name is invalid")
    custody.require(cfg["bucket_location"] in ("EU", "US", "ASIA"), "explicit multi-region destination is required")
    custody.positive_int(cfg["retention_days"], 30, 3650, "custody retention must be at least 30 days")
    custody.require(isinstance(cfg["billing_account"], str) and re.fullmatch(r"[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}",
                    cfg["billing_account"]), "actual custodian-approved billing account is required")
    custody.require(not (cfg["organization_id"] and cfg["folder_id"]), "choose an organization, a folder, or explicit standalone ownership")
    for field in ("organization_id", "folder_id"):
        custody.require(cfg[field] is None or isinstance(cfg[field], str) and re.fullmatch(r"[1-9][0-9]{5,20}", cfg[field]),
                        "parent governance identifier is invalid")
    custody.require(isinstance(cfg["age_public_recipient"], str) and re.fullmatch(r"age1[a-z0-9]{58,80}", cfg["age_public_recipient"]),
                    "actual custodian age X25519 public recipient is required")
    custody.require(cfg["independence_reviewed"] is True, "independent governance review must be recorded")
    custody.label(cfg["governance_review_reference"])
    custody.require("REPLACE" not in cfg["governance_review_reference"].upper(), "actual governance review reference is required")
    now = int(time.time()) if now is None else now
    custody.require(type(cfg["review_expires_at_utc"]) is int and now < cfg["review_expires_at_utc"] <= now + 366 * 86400,
                    "governance review is expired or unbounded")
    return cfg


def plan(cfg, now=None):
    validate(cfg, now)
    target, bucket = cfg["recovery_project_id"], "gs://" + cfg["recovery_bucket_name"]
    account = "--account=" + cfg["provisioner_account"]
    commands = []

    def step(identifier, args, phase="provision", actor="independent_custodian"):
        commands.append({"id": identifier, "phase": phase, "actor": actor,
                         "argv": ["gcloud", *args, account], "execute_automatically": False})

    step("verify_explicit_custodian_identity", ["auth", "list", "--filter=account:" + cfg["provisioner_account"], "--format=json"], "read_only")
    step("verify_billing_context", ["billing", "accounts", "describe", cfg["billing_account"], "--format=json"], "read_only")
    create = ["projects", "create", target, "--name=CipherVault Independent Recovery"]
    if cfg["folder_id"]:
        create.append("--folder=" + cfg["folder_id"])
    elif cfg["organization_id"]:
        create.append("--organization=" + cfg["organization_id"])
    step("create_separate_project", create)
    step("attach_approved_billing", ["billing", "projects", "link", target, "--billing-account=" + cfg["billing_account"]])
    step("enable_storage", ["services", "enable", "storage.googleapis.com", "--project=" + target])
    for index, principal in enumerate(sorted(set(cfg["custody_admin_principals"]))):
        step("grant_custody_admin_" + str(index), ["projects", "add-iam-policy-binding", target,
                                                 "--member=" + principal, "--role=roles/owner"])
    step("create_private_retained_bucket", ["storage", "buckets", "create", bucket, "--project=" + target,
                                           "--location=" + cfg["bucket_location"], "--default-storage-class=STANDARD",
                                           "--uniform-bucket-level-access", "--public-access-prevention",
                                           "--retention-period=" + str(cfg["retention_days"]) + "d", "--soft-delete-duration=7d"])
    step("enable_object_versions", ["storage", "buckets", "update", bucket, "--versioning"])
    step("create_policy_read_role", ["iam", "roles", "create", "cvCustodyPolicyReader", "--project=" + target,
                                    "--title=CipherVault custody policy reader", "--stage=GA",
                                    "--permissions=storage.buckets.get,storage.buckets.getIamPolicy"])
    role = "projects/" + target + "/roles/cvCustodyPolicyReader"
    uploader = cfg["production_uploader_principal"]
    step("grant_production_create_only", ["storage", "buckets", "add-iam-policy-binding", bucket,
                                         "--member=" + uploader, "--role=roles/storage.objectCreator"])
    step("grant_production_policy_read", ["storage", "buckets", "add-iam-policy-binding", bucket,
                                         "--member=" + uploader, "--role=" + role])
    for index, principal in enumerate(sorted(set(cfg["restore_principals"]))):
        step("grant_restore_read_" + str(index), ["storage", "buckets", "add-iam-policy-binding", bucket,
                                                "--member=" + principal, "--role=roles/storage.objectViewer"])
        step("grant_restore_policy_read_" + str(index), ["storage", "buckets", "add-iam-policy-binding", bucket,
                                                       "--member=" + principal, "--role=" + role])
    step("inspect_before_lock", ["storage", "buckets", "describe", bucket, "--raw", "--format=json"], "read_only")
    step("inspect_iam_before_lock", ["storage", "buckets", "get-iam-policy", bucket, "--format=json"], "read_only")
    step("custodian_reviewed_retention_lock", ["storage", "buckets", "update", bucket, "--lock-retention-period"], "irreversible_retention_lock")
    step("capture_final_bucket_evidence", ["storage", "buckets", "describe", bucket, "--raw", "--format=json"], "read_only")
    step("capture_project_number", ["projects", "describe", target, "--format=value(projectNumber)"], "read_only")
    return {"schema_version": 1, "status": "reviewable_plan_only", "cloud_mutated": False,
            "independent_custody_certified": False, "recovery_project_id": target, "bucket": bucket,
            "bucket_location": cfg["bucket_location"], "retention_days": cfg["retention_days"],
            "archive_encryption": "age_x25519", "age_public_recipient": cfg["age_public_recipient"],
            "production_data_permissions": "object_create_only", "restore_data_permissions": "object_read_only",
            "offline_keys_uploaded": False, "commands": commands,
            "external_acceptance": ["actual custodian identity and group/inherited IAM separation", "billing/parent/project deletion authority",
                                    "separately retained historical keys and real age interoperability", "first production upload and independent restore",
                                    "two-host scheduling and stale/failure alert delivery", "independently anchored authenticity evidence"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="new plan file inside an existing owner-only directory")
    args = parser.parse_args()
    try:
        cfg = custody.json_load(custody.checked_path(str(args.config.resolve())))
        result = plan(cfg)
        if args.output:
            output = args.output.absolute()
            custody.private(custody.checked_path(str(output.parent), True))
            custody.require(not output.exists(), "plan output must not already exist")
            custody.json_write(output, result)
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        message = str(error) if isinstance(error, custody.CustodyError) else "provisioning plan validation failed; details suppressed"
        print(json.dumps({"status": "incomplete_configuration", "cloud_mutated": False, "error": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
