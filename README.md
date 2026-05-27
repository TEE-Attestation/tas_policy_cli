# tas-policy-cli

A command-line tool for managing attestation policies on a
[TEE Attestation Service (TAS)](https://github.com/TEE-Attestation/tas) server.

It supports **Intel TDX** and **AMD SEV-SNP** confidential virtual machines,
letting you create, update, list, get, delete and diagnose connectivity to policies directly from the
terminal.

> **New to TAS?** See the
> [TAS repository](https://github.com/TEE-Attestation/tas) for instructions on
> setting up a server and details of what a TAS policy looks like.

## Contents

- [Installation](#installation)
- [Signing key setup](#signing-key-setup)
- [Quick start](#quick-start)
- [Global options](#global-options)
- [Commands](#commands) — [create](#create--create-a-new-policy) · [list](#list--list-policies) · [get](#get--get-a-single-policy) · [update](#update--update-an-existing-policy) · [delete](#delete--delete-a-policy) · [healthcheck](#healthcheck--diagnose-connectivity)
- [Policy examples](#policy-examples) — [Intel TDX](#intel-tdx--default-tcb-only-policy) · [AMD SEV-SNP](#amd-sev-snp--default-genoa-policy)
- [Verbose logging](#verbose-logging)
- [Licence](#licence)

## Installation

```bash
# Clone and build from source
git clone https://github.com/TEE-Attestation/tas-policy-cli
cd tas-policy-cli
cargo build --release

# The binary is at target/release/tas-policy
```

## Signing key setup

Policies must be cryptographically signed before they can be uploaded.
The CLI uses **RSA-PSS with SHA-384** and accepts PEM-encoded private keys in
either PKCS#8 or traditional PKCS#1 format.

### Generate a key pair

```bash
# Generate a 3072-bit RSA private key (PKCS#8 PEM, no passphrase)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out signing-key.pem

# Extract the public key
openssl pkey -in signing-key.pem -pubout -out signing-key-pub.pem
```

Optionally, to protect the private key with a passphrase:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -aes-256-cbc -out signing-key.pem

# Store the passphrase in a file so the CLI can read it
echo -n 'my-passphrase' > signing-key-pass.txt
chmod 600 signing-key-pass.txt

# Then pass it when creating or updating a policy
tas-policy create --signing-key signing-key.pem \
  --signing-key-pass-file signing-key-pass.txt ...
```

### Register the public key with TAS

The TAS server needs the **public key** so it can verify policy signatures.
Copy it into the server's signing keys directory:

```bash
# Copy the public key to the TAS server's keys folder
scp signing-key-pub.pem user@tas-server:/opt/tas/config/signing-keys/
```

> The exact path depends on your TAS deployment. See the
> [TAS repository](https://github.com/TEE-Attestation/tas) for the server's
> directory layout and configuration.

## Quick start

Every command needs to know where the TAS server is. You can pass connection
options as flags or set them as environment variables:

```bash
# Using flags
tas-policy list \
  --tas-host my-tas-server.example.com \
  --api-key-file ~/.tas/api.key \
  --tls-ca-cert /etc/ssl/tas-ca.pem

# Or using environment variables
export TAS_HOST=my-tas-server.example.com
export TAS_API_KEY_FILE=~/.tas/api.key
export TAS_TLS_CA_CERT=/etc/ssl/tas-ca.pem
tas-policy list
```

## Global options

These options apply to every command and can be placed before or after the
subcommand.

| Flag | Env var | Description |
|------|---------|-------------|
| `--tas-host` | `TAS_HOST` | TAS server hostname or IP address |
| `--tas-port` | `TAS_PORT` | TAS server port (default: 5001) |
| `--api-key-file` | `TAS_API_KEY_FILE` | Path to API key file |
| `--tls-ca-cert` | `TAS_TLS_CA_CERT` | PEM-encoded CA certificate bundle |
| `--no-tls` | `TAS_NO_TLS` | Disable TLS (use plain HTTP) |
| `--output-format` | | Output format: `human` (default) or `json` |
| `--non-interactive` | | Suppress interactive prompts |
| `-v`, `--verbose` | | Increase log verbosity (`-v` info, `-vv` debug) |
| `--version` | | Print version and exit |

## Commands

### `create` — Create a new policy

Create and upload a signed attestation policy. You must specify the CVM type
(`TDX` or `SEV`) and provide a signing key.

#### Common options

| Flag | Description |
|------|-------------|
| `--policy-id` | Unique policy identifier (required) |
| `--cvm-type` | CVM type: `TDX` or `SEV` (required) |
| `--key-id` | Unique KMS key identifier (required) |
| `--signing-key` | Path to signing key PEM file (required) |
| `--signing-key-pass-file` | Path to file containing the signing key passphrase |
| `--name` | Human-readable policy name (required) |
| `--description` | Policy description |
| `--dry-run` | Preview the signed policy JSON without uploading |

```bash
# Create a TDX policy with measurement registers
tas-policy create \
  --policy-id tdx-prod-policy \
  --cvm-type TDX \
  --key-id tdx-prod-release-key \
  --signing-key signing-key.pem \
  --name "Production TDX Policy" \
  --description "TDX policy for production workloads" \
  --mrtd a1b2c3...  \ # replace with actual MRTD (96 hex chars)
  --rtmr0 000102...    # replace with actual RTMR0 (96 hex chars)

# Create a TDX fleet-wide policy (TCB checks only, no measurements)
tas-policy create \
  --policy-id fleet-tdx-policy \
  --cvm-type TDX \
  --key-id fleet-tdx-release-key \
  --signing-key signing-key.pem \
  --tcb-only \
  --platform-tcb up-to-date \
  --tdx-module-tcb up-to-date

# Create an AMD SEV-SNP policy (SVN levels default to per-family values)
tas-policy create \
  --policy-id sev-prod-policy \
  --cvm-type SEV \
  --key-id sev-prod-release-key \
  --signing-key signing-key.pem \
  --processor-family genoa \
  --measurement a1b2c3...  # replace with your actual launch measurement (96 hex chars)

# Preview without uploading
tas-policy create --policy-id test-policy --cvm-type TDX --key-id test-release-key --signing-key key.pem --tcb-only --dry-run
```

#### TDX-specific options

| Flag | Description |
|------|-------------|
| `--mrtd` | Build-time measurement of TD (96 hex chars) |
| `--rtmr0` | Firmware measurement register (96 hex chars) |
| `--rtmr1` | OS/bootloader measurement register (96 hex chars) |
| `--rtmr2` | Application measurement register (96 hex chars) |
| `--rtmr3` | Runtime measurement register (96 hex chars) |
| `--mrconfigid` | Configuration ID measurement (96 hex chars) |
| `--mrowner` | Owner measurement (96 hex chars) |
| `--mrownerconfig` | Owner configuration measurement (96 hex chars) |
| `--tcb-only` | TCB-only mode — no measurements, fleet-wide policy |
| `--tcb-update` | TCB update policy: `standard` (default) or `early` |
| `--platform-tcb` | Platform TCB status: `up-to-date`, `out-of-date`, `revoked` |
| `--tdx-module-tcb` | TDX Module TCB status: `up-to-date`, `out-of-date`, `revoked` |
| `--qe-tcb` | Quoting Enclave TCB status: `up-to-date`, `out-of-date`, `revoked` |
| `--min-tee-tcb-svn` | Minimum TEE TCB SVN |

#### SEV-specific options

| Flag | Description |
|------|-------------|
| `--processor-family` | AMD processor family: `milan`, `genoa`, or `turin` (required) |
| `--measurement` | Launch measurement (96 hex chars) |
| `--host-data` | Host-provided data hash (96 hex chars) |
| `--svn-only` | SVN-only mode — no measurement required |
| `--min-boot-loader-svn` | Minimum PSP Bootloader SVN (default: per-family) |
| `--min-tee-svn` | Minimum PSP OS (TEE) SVN (default: per-family) |
| `--min-snp-svn` | Minimum SNP firmware SVN (default: per-family) |
| `--min-microcode-svn` | Minimum CPU microcode SVN (default: per-family) |
| `--min-ucode-svn` | Minimum UCODE_SVN (required for Turin) |
| `--min-snp-iface-ver` | Minimum SNP_IFACE_VER (required for Turin) |
| `--vmpl` | Required VMPL level (0–3) |
| `--debug-allowed` | Allow debugging |
| `--migrate-ma-allowed` | Allow migration |
| `--smt-allowed` | Allow SMT/hyperthreading |
| `--ecc-enabled` | Require ECC memory on host |
| `--tsme-enabled` | Require Transparent SME on host |
| `--alias-check-complete` | Require alias check completed |
| `--smt-enabled` | Require SMT enabled on host |

### `list` — List policies

```bash
# List all policies
tas-policy list

# Filter by CVM type
tas-policy list --filter-type TDX

# Filter by key-id prefix
tas-policy list --key-id-prefix my-project

# Show full policy details (makes an extra HTTP call per policy)
tas-policy list --full

# Output as JSON
tas-policy list --output-format json
```

| Flag | Description |
|------|-------------|
| `--filter-type` | Filter by CVM type: `TDX` or `SEV` |
| `--key-id-prefix` | Filter by key-id prefix |
| `--full` | Fetch and display full policy details |

### `get` — Get a single policy

```bash
# Get a policy by its policy ID
tas-policy get --policy-id my-tdx-policy

# Output as JSON for scripting
tas-policy get --policy-id my-sev-policy --output-format json
```

| Flag | Description |
|------|-------------|
| `--policy-id` | Policy ID (e.g. `my-tdx-policy`) |

### `update` — Update an existing policy

Fetches the existing policy, merges your changes, re-signs it and uploads the
new version. Only the fields you specify are changed; everything else is kept.
`--signing-key` is required because the updated policy must be re-signed.

```bash
# Update a TDX policy's measurement
tas-policy update \
  --policy-id my-tdx-policy \
  --signing-key signing-key.pem \
  --mrtd aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Update an SEV policy's description
tas-policy update \
  --policy-id my-sev-policy \
  --signing-key signing-key.pem \
  --description "Updated policy for production"

# Preview merged policy without uploading
tas-policy update \
  --policy-id my-tdx-policy \
  --signing-key signing-key.pem \
  --name "New name" \
  --dry-run
```

The update command accepts the same TDX and SEV measurement/TCB flags as
`create`. Only the flags you provide are changed.

### `delete` — Delete a policy

Deletes a policy from the TAS server. The CLI will prompt for confirmation
before proceeding. Pass `--non-interactive` to skip the prompt.

```bash
# Interactive (asks "Delete policy 'my-tdx-policy'?")
tas-policy delete --policy-id my-tdx-policy

# Non-interactive (no confirmation prompt)
tas-policy delete --policy-id my-tdx-policy --non-interactive
```

| Flag | Description |
|------|-------------|
| `--policy-id` | Policy ID to delete |

### `healthcheck` — Diagnose connectivity

Runs layered connectivity checks against the TAS server and reports
pass/fail for each layer with latency and diagnostic detail. Use it to
pinpoint exactly where a connection problem occurs.

The checks run in order and **short-circuit on failure** — if DNS fails,
TCP/TLS/HTTP checks are skipped:

1. **DNS Resolution** — resolves the hostname, reports the IP(s).
2. **TCP Connection** — connects to the resolved address (5 s timeout).
3. **TLS Handshake** — verifies the server certificate (skipped with `--no-tls`).
4. **HTTP Request** — sends `GET /policy/v0/list` and reports the status code.
5. **API Authentication** — reports whether the API key was accepted (skipped
   if `--api-key-file` is not provided).

```bash
# Full check (DNS → TCP → TLS → HTTP → Auth)
tas-policy healthcheck \
  --tas-host my-tas-server.example.com \
  --tls-ca-cert /etc/ssl/tas-ca.pem \
  --api-key-file ~/.tas/api.key

# Check without TLS (plain HTTP)
tas-policy healthcheck \
  --tas-host my-tas-server.example.com \
  --no-tls

# Network-only check (skip auth)
tas-policy healthcheck \
  --tas-host my-tas-server.example.com \
  --tls-ca-cert /etc/ssl/tas-ca.pem

# Machine-readable output
tas-policy healthcheck \
  --tas-host my-tas-server.example.com \
  --tls-ca-cert /etc/ssl/tas-ca.pem \
  --output-format json
```

Example human-readable output:

```
Checking connectivity to my-tas-server.example.com:5001 ...

 ✓ DNS Resolution  2ms  resolved to: 10.0.1.42
 ✓ TCP Connection  5ms  connected to 10.0.1.42:5001
 ✓ TLS Handshake  45ms  TLS connection established
 ✓ HTTP Request  48ms  HTTP 200
 ✓ API Authentication  API key accepted (HTTP 200)

All checks passed (5/5)
```

When a check fails the command exits with code 1 and shows the failure:

```
 ✓ DNS Resolution  1ms  resolved to: 10.0.1.42
 ✗ TCP Connection  5002ms  failed to connect to 10.0.1.42:5001: Connection refused

1 of 2 checks failed
```

`--api-key-file` is **optional** for `healthcheck`. If omitted, the
authentication check is shown as skipped so you can still diagnose
network/TLS issues without an API key.

## Policy examples

The examples below show how to create a default policy for each CVM type and
what the resulting policy JSON looks like when stored on the TAS server.

### Intel TDX — default TCB-only policy

A TCB-only policy enforces platform firmware levels without pinning individual
measurement registers, making it suitable for fleet-wide deployments.

```bash
tas-policy create \
  --cvm-type TDX \
  --key-id my-tdx-policy \
  --signing-key signing-key.pem \
  --name "Default TDX Policy" \
  --description "Fleet-wide TDX TCB policy" \
  --tcb-only \
  --platform-tcb up-to-date \
  --tdx-module-tcb up-to-date \
  --qe-tcb up-to-date
```

The resulting policy stored on the server:

```json
{
  "metadata": {
    "policy_type": "TDX",
    "key_id": "my-tdx-policy",
    "name": "Default TDX Policy",
    "description": "Fleet-wide TDX TCB policy"
  },
  "validation_rules": {
    "tcb": {
      "update": "standard",
      "platform_tcb": "UpToDate",
      "tdx_module_tcb": "UpToDate",
      "qe_tcb": "UpToDate"
    }
  },
  "signature": {
    "algorithm": "SHA384",
    "padding": "PSS",
    "value": "<base64-encoded-signature>"
  }
}
```

Because `--tcb-only` is set, no `body` (measurement registers) section appears
in the policy. The server will verify only that the platform firmware meets the
required TCB levels.

### AMD SEV-SNP — default Genoa policy

The only required SEV-specific flag is `--processor-family`. When SVN levels
are omitted, the CLI fills in hardcoded defaults for the selected family.

```bash
tas-policy create \
  --cvm-type SEV \
  --key-id my-sev-genoa-policy \
  --signing-key signing-key.pem \
  --name "Default SEV Genoa Policy" \
  --description "SEV-SNP policy for AMD Genoa processors" \
  --processor-family genoa
```

The resulting policy stored on the server:

```json
{
  "metadata": {
    "policy_type": "SEV",
    "key_id": "my-sev-genoa-policy",
    "name": "Default SEV Genoa Policy",
    "description": "SEV-SNP policy for AMD Genoa processors"
  },
  "validation_rules": {
    "policy": {
      "debug_allowed": false,
      "migrate_ma_allowed": false
    },
    "current_tcb": {
      "bootloader": { "min_value": 12 },
      "tee":        { "min_value": 0 },
      "snp":        { "min_value": 28 },
      "microcode":  { "min_value": 88 }
    },
    "committed_tcb": {
      "bootloader": { "min_value": 12 },
      "tee":        { "min_value": 0 },
      "snp":        { "min_value": 28 },
      "microcode":  { "min_value": 88 }
    },
    "launch_tcb": {
      "bootloader": { "min_value": 12 },
      "tee":        { "min_value": 0 },
      "snp":        { "min_value": 28 },
      "microcode":  { "min_value": 88 }
    },
    "platform_info": {
      "ecc_enabled":          { "boolean": true },
      "tsme_enabled":         { "boolean": true },
      "alias_check_complete": { "boolean": true },
      "smt_enabled":          { "boolean": true }
    }
  },
  "signature": {
    "algorithm": "SHA384",
    "padding": "PSS",
    "value": "<base64-encoded-signature>"
  }
}
```

Because no `--measurement` or `--vmpl` flag was given, neither field appears in
the policy — the server will not enforce a specific launch digest or VMPL level.

> **Note:** The SVN defaults above are **hardcoded per processor family** in the
> CLI and are not queried from the TAS server at runtime. This differs from the
> Intel TDX case, where TCB status values like `UpToDate` are evaluated
> dynamically by the server during attestation. If AMD publishes new minimum SVN
> levels for your processor family, you must explicitly pass the updated
> `--min-*-svn` flags or wait for a CLI update.
>
> | Family | bootloader | tee | snp | microcode | ucode | snp_iface_ver |
> |--------|-----------|-----|-----|-----------|-------|---------------|
> | Milan  | 1         | 1   | 1   | 1         | —     | —             |
> | Genoa  | 12        | 0   | 28  | 88        | —     | —             |
> | Turin  | 1         | 1   | 1   | 1         | 1     | 1             |

## Verbose logging

Use `-v` for informational messages or `-vv` for debug output. The flag works
before or after the subcommand:

```bash
tas-policy -v list
tas-policy list -vv --filter-type TDX
```

Set `RUST_LOG` to override the flag (e.g. `RUST_LOG=trace`).
`-v` is equivalent to `RUST_LOG=info`, `-vv` to `RUST_LOG=debug`.

All connection options listed in [Global options](#global-options) can also be
set via the corresponding environment variable (see the "Env var" column).
`RUST_LOG` is the only additional variable that is not exposed as a flag.

## Contributing

Contributing to the project is simple! Just send a pull request through GitHub. For detailed instructions on formatting your changes and following our contribution guidelines, take a look at the [CONTRIBUTING](./CONTRIBUTING.md)  file.

## Licence

[MIT](LICENSE) — Copyright 2026 Hewlett Packard Enterprise Development LP.
