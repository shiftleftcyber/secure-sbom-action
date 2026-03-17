# Secure SBOM GitHub Action

[![GitHub release](https://img.shields.io/github/v/release/shiftleftcyber/secure-sbom-action)]()
[![License](https://img.shields.io/github/license/shiftleftcyber/secure-sbom-action)]()

The Secure SBOM GitHub Action signs and verifies Software Bill of Materials (SBOMs) and cryptographic digests
using the SecureSBOM API from [ShiftLeftCyber](https://shiftleftcyber.io).

This enables organizations to cryptographically attest to the integrity of SBOMs generated during CI/CD pipelines.

# Features

- Sign SBOMs using SecureSBOM managed keys
- Verify signed SBOMs during CI/CD
- Sign cryptographic digests when sending full SBOMs is not practical
- Supports CycloneDX SBOMs
- Supports v1 and v2 SecureSBOM APIs
- Backwards compatible with legacy inputs

# Example Workflows

## Sign an SBOM

```yaml
name: Sign SBOM

on: [push]

jobs:
  sign:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Sign SBOM
        uses: shiftleftcyber/secure-sbom-action@v2
        with:
          secure_sbom_api_key: ${{ secrets.SECURE_SBOM_API_KEY }}
          secure_sbom_signing_key_id: ${{ vars.SECURE_SBOM_KEY_ID }}
          secure_sbom_action: sign_sbom
          sbom_file: ./sbom.json
```

After signing, the action produces:

`sbom.signed.json`

## Verify a Signed SBOM

```yaml
name: Verify SBOM

on: [push]

jobs:
  verify:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Verify SBOM
        uses: shiftleftcyber/secure-sbom-action@v2
        with:
          secure_sbom_api_key: ${{ secrets.SECURE_SBOM_API_KEY }}
          secure_sbom_signing_key_id: ${{ vars.SECURE_SBOM_KEY_ID }}
          secure_sbom_action: verify_sbom
          sbom_file: ./sbom.signed.json
```

## Sign a Digest

Some environments cannot send full SBOMs to external services.
In these cases you can sign a SHA256 digest instead.

```bash
digest=$(openssl dgst -sha256 -binary sbom.json | base64)
```

GitHub Workflow

```yaml
- name: Sign Digest
  uses: shiftleftcyber/secure-sbom-action@v2
  with:
    secure_sbom_api_key: ${{ secrets.SECURE_SBOM_API_KEY }}
    secure_sbom_signing_key_id: ${{ vars.SECURE_SBOM_KEY_ID }}
    secure_sbom_action: sign_digest
    digest: ${{ steps.generate_digest.outputs.digest }}
```

# Inputs

| Name                         | Description                                         | Required                         |
| ---------------------------- | --------------------------------------------------- | -------------------------------- |
| `secure_sbom_api_key`        | Preferred API key for SecureSBOM authentication     | ✅                                |
| `secure_sbom_signing_key_id` | Preferred key ID used for signing or verifying      | ✅                                |
| `secure_sbom_action`         | Action to perform (`sign`, `verify`, `sign_digest`) | ❌ (default `sign`)               |
| `sbom_file`                  | Path to SBOM file for signing or verification       | Required for `sign` and `verify` |
| `digest`                     | Base64 encoded SHA256 digest                        | Required for `sign_digest`       |
| `secure_sbom_api_url`        | Optional SecureSBOM API base URL                    | ❌                                |
| `secure_sbom_use_v1_api`     | Use legacy v1 SBOM API instead of v2                | ❌                                |

# Deprecated Inputs (Still Supported)

The following legacy inputs are still supported for backwards compatibility:

| Deprecated Input | Replacement                  |
| ---------------- | ---------------------------- |
| `api_key`        | `secure_sbom_api_key`        |
| `key_id`         | `secure_sbom_signing_key_id` |
| `action`         | `secure_sbom_action`         |
| `api_url`        | `secure_sbom_api_url`        |

When deprecated inputs are used, the action logs a warning.

# API Versions

The action uses SecureSBOM API v2 by default.

To force use of the legacy API:

```yaml
secure_sbom_use_v1_api: true
```

# Output Files

When signing SBOMs, the action produces:

`<input>.signed.<ext>`

Example:

`sbom.json → sbom.signed.json`

# SecureSBOM Platform

SecureSBOM provides a cloud-native service for signing and verifying SBOMs used in modern software supply chain
security.

Capabilities include:
- SBOM signing
- signature verification
- CI/CD integrations
- key management
- supply chain integrity validation

Learn more:
https://shiftleftcyber.io

# Security Best Practices 

Always store API keys in GitHub Secrets:

`Settings → Secrets → Actions`

Example:

```bash
SECURE_SBOM_API_KEY
```

# License

Apache-2.0

© ShiftLeftCyber
