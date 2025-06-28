# Secure SBOM GitHub Action

This GitHub Action signs and verifies SBOMs using the [SecureSBOM from ShiftLeftCyber](https://shiftleftcyber.io).

## Features
 ✅ Sign SBOMs with a given key

 ✅ Verify signed SBOMs with a given key

## Usage

```yaml
name: Sign SBOM
on: [push]

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sign SBOM
        uses: shiftleftcyber/secure-sbom-action@v1
        with:
          sbom_file: <</path/to/sbom/file>>
          secure_sbom_action: sign
          api_key: ${{ secrets.SBOM_API_KEY }}
          key_id: ${{ secrets.SECURE_SBOM_KEYID }}
```

```yaml
name: Verify SBOM
on: [push]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sign SBOM
        uses: shiftleftcyber/secure-sbom-action@v1
        env:
          SBOM_FILE: <</path/to/signed/sbom/file>>
          SECURE_SBOM_ACTION: verify
          API_KEY: ${{ secrets.SBOM_API_KEY }}
          KEY_ID: ${{ secrets.SECURE_SBOM_KEYID }}
```


## Inputs

| Name           | Description                            | Required | Default  |
|----------------|----------------------------------------|---------- |----------|
| `SBOM_FILE`     | Path to the SBOM to sign or verify    | 🚫        | sign     |
| `KEY_ID`       | Key ID to use for signing/verification | ✅        | —        |
| `API_KEY`      | API Key (use GitHub Secret)            | ✅        | —        |
| `ACTION`       | `sign` or `verify`                     | ✅        | —        |
