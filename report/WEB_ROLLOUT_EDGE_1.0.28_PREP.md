# Web rollout prep: edge images for 1.0.28 + explorer guidance (1+2)

Source commit `fe901c9` (contains `c883acc` explorer guidance). Edge build
run 37132439045 in progress at prep time — grab digests when green.

## New digests (fill in from the green run)

```powershell
$DASH_NEW  = "ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:<from main-fe901c9 tag>"
$ACCT_NEW  = "ghcr.io/samuel-1-avson/ciphervault-account@sha256:<from main-fe901c9 tag>"
```

Resolve via: `gh api
repos/samuel-1-avson/CipherVault/packages/container/ciphervault-dashboard/versions`
or `docker buildx imagetools inspect ghcr.io/...:main-fe901c9 --format
'{{json .Manifest}}'`. Verify cosign (keyless, edge-images identity) before
promoting — the script does this itself and refuses unsigned digests.

## Rollback digests (live at prep time, 2026-10-03)

```powershell
$DASH_ROLLBACK = "ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:a2cee5149746462d20b16f26c792964f66211c491d2833cd8301caac7598c123"
$ACCT_ROLLBACK = "ghcr.io/samuel-1-avson/ciphervault-account@sha256:92a7d03ea7772c08192ebf5d423dc531ca6aa7a97b8f0abf4d7e296bac33836d"
```

Re-read from instance metadata at rollout time in case anything moved.

## Promotion command (needs explicit owner go-ahead)

```powershell
.\scripts\gcp\promote-immutable-web.ps1 `
  -DashboardImage $DASH_NEW `
  -AccountImage $ACCT_NEW `
  -RollbackDashboardImage $DASH_ROLLBACK `
  -RollbackAccountImage $ACCT_ROLLBACK `
  -OperatorEndpoints "https://op1.cipherv.online https://op2.cipherv.online https://op3.cipherv.online" `
  -RuntimeServiceAccount "cv-web-runtime@gen-lang-client-0022105784.iam.gserviceaccount.com" `
  -ExpectedBuildVersion "1.0.28" `
  -ProjectId "gen-lang-client-0022105784" `
  -InstanceName "cv-web-ui" `
  -Zone "us-east1-b" `
  -OperatorPins @("https://op1.cipherv.online=92a9a900e930412c8ff3aced141e9859fa2e0a0b8177e7ca72be4e8c912b41b6;https://op2.cipherv.online=0<full-value-from-metadata>;...") `
  -OperatorRegions "us-central1=https://op1.cipherv.online https://op2.cipherv.online;us-east1=https://op3.cipherv.online" `
  -FinalityConfirmations "64" `
  -CheckpointPublisherKey "5631c3669259b6345cc3572b310bef8403cb5249717faaa31f371607b5623052" `
  -ArbitrumRpcUrl "https://sepolia-rollup.arbitrum.io/rpc" `
  -CosignCertificateIdentityRegex "https://github.com/samuel-1-avson/CipherVault/.github/workflows/edge-images.yml@refs/heads/main"
```

Notes:

- Run first WITHOUT `-Apply` (dry run), review, then re-run WITH `-Apply`.
- OperatorPins above is truncated in this note — copy the full
  `operator-pins` metadata value at rollout time (semicolons survive
  metadata transport; the script passes them through).
- The script cosign-verifies both new digests, updates instance metadata,
  restarts the unit, health-checks `/api/vault` + `/api/context`, and
  keeps rollback metadata staged.
- Post-rollout: `GET https://vault.cipherv.online/api/context`
  `build_version` must read `1.0.28`, and the Recovery tab must show the
  new notice. Record the promoted digests (edge builds share the version
  string, so the version check alone cannot distinguish them).
- Rollback: re-run with the rollback digests as the new images (the
  script stages rollback metadata automatically).
