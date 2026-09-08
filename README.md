# DocVerify

**Document integrity verification using SHA-256 hashing and RSA-PSS digital signatures.**

A lightweight, open-source, command-line tool for detecting tampering and verifying authenticity of any file — no proprietary software, cloud services, or vendor lock-in required.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## Overview

In finance, law, healthcare, and academia, electronic documents are constantly exchanged — yet traditional physical signatures and seals offer no way to detect if a digital file has been altered, or to confirm who actually produced it. Enterprise PKI systems and proprietary e-signing platforms solve this, but at the cost of complexity, licensing fees, and infrastructure most individuals and small teams don't need.

**DocVerify** closes that gap with a simple, self-contained CLI workflow built on two complementary cryptographic guarantees:

1. **Integrity** — a SHA-256 hash of the file detects even a single-bit modification.
2. **Authenticity** — an RSA-PSS digital signature over that hash proves who signed the document and that the signature hasn't been forged.

The result is a three-command workflow (`generate-keys` → `sign` → `verify`) that works identically on Windows, Linux, and macOS, on any file type, with no external dependencies beyond Python's `cryptography` library.

## Features

- 🔑 **RSA key pair generation** — 1024 / 2048 (default) / 4096-bit, exported as standard PEM files
- 🧮 **Stream-based SHA-256 hashing** — reads files in 8 KB chunks, so file size is never limited by available memory
- ✍️ **RSA-PSS digital signatures** (SHA-256 + MGF1) — the modern, provably-secure successor to PKCS#1 v1.5 padding
- 📦 **Portable signature metadata** — every signature is exported as a self-describing `.sig.json` file (hash, signature, algorithm, key size, timestamp) that can be stored or transmitted independently of the tool
- 🛡️ **Two-layer verification** — hash comparison (has it changed?) and signature validation (who signed it?) are checked and reported separately, so failures are diagnosable
- 🗂️ **File-type agnostic** — works on PDFs, Word docs, images, archives, or any other binary/text file
- 🖥️ **Zero-dependency CLI** — built entirely on Python's standard library plus `pyca/cryptography`; no servers, databases, or network calls
- 🧰 **Utility commands** — `hash` for a quick standalone SHA-256 digest, `inspect` for reading a `.sig.json` file's contents

## How It Works

```
                ┌──────────────┐
                │   Document   │
                └──────┬───────┘
                       │
              ┌────────▼─────────┐
              │  SHA-256 Hashing │  (streamed, 8 KB chunks)
              └────────┬─────────┘
                       │
              ┌────────▼──────────┐
              │  RSA-PSS Signing  │  (signed with private key)
              └────────┬──────────┘
                       │
              ┌────────▼──────────┐
              │  <file>.sig.json  │  (hash + signature + metadata)
              └────────┬──────────┘
                       │
        ── share the document + .sig.json + public key ──
                       │
              ┌────────▼──────────┐
              │   Verification    │  (recompute hash, check signature)
              └────────┬──────────┘
                       │
            ┌──────────▼───────────┐
            │  VERIFIED / FAILED   │
            └───────────────────────┘
```

<img src="docs/images/architecture-diagram.png" alt="DocVerify architecture diagram" width="800">

The system is organized into five logical modules:

| Module | Responsibility |
|---|---|
| **Key Management** | Generates RSA key pairs and reads/writes them in PEM format |
| **Hashing Engine** | Computes SHA-256 digests using chunked, stream-based file reads |
| **Signing Engine** | Signs a document's hash with RSA-PSS and exports `.sig.json` metadata |
| **Verification Engine** | Recomputes the hash and validates the signature against a public key |
| **CLI Interface** | Exposes everything as `argparse` subcommands |

## Installation

```bash
git clone https://github.com/Akilancs/docverify.git
cd docverify
pip install -r requirements.txt
```

Requires **Python 3.10+**.

## Usage

### 1. Generate a key pair

```bash
$ python docverify.py generate-keys
```

<img src="docs/images/demo-generate-keys.png" alt="generate-keys demo" width="600">

By default this writes `private_key.pem` and `public_key.pem` to the current directory. Options:

| Flag | Description | Default |
|---|---|---|
| `--private-key PATH` | Output path for the private key | `private_key.pem` |
| `--public-key PATH` | Output path for the public key | `public_key.pem` |
| `--bits {1024,2048,4096}` | RSA key size | `2048` |
| `--force` | Overwrite existing key files | off |

> ⚠️ Keep `private_key.pem` secret. Only distribute the public key.

### 2. Sign a document

```bash
$ python docverify.py sign report.pdf --key private_key.pem
```

<img src="docs/images/demo-sign.png" alt="sign demo" width="600">

This computes the file's SHA-256 hash, signs it with RSA-PSS, and writes `report.pdf.sig.json` alongside the original file.

| Flag | Description | Default |
|---|---|---|
| `file` | Path to the document to sign | required |
| `--key PATH` | Private key to sign with | `private_key.pem` |
| `--output, -o PATH` | Output path for the signature file | `<file>.sig.json` |

### 3. Verify a document

```bash
$ python docverify.py verify report.pdf --key public_key.pem
```

<img src="docs/images/demo-verify.png" alt="verify demo" width="600">

Recomputes the hash and checks the signature. Exits with code `0` if verified, `1` if verification fails (useful for scripting/CI).

| Flag | Description | Default |
|---|---|---|
| `file` | Path to the document to verify | required |
| `--key PATH` | Public key to verify against | `public_key.pem` |
| `--sig PATH` | Path to the `.sig.json` file | `<file>.sig.json` |

If the document was modified after signing, the hash comparison fails and a diagnostic is printed. If the hash matches but the signature is invalid, that indicates the wrong public key was used.

### Utility commands

```bash
# Print the SHA-256 digest of any file
$ python docverify.py hash report.pdf

# Inspect a signature metadata file
$ python docverify.py inspect report.pdf.sig.json
```

## Signature Metadata Format

Every `sign` operation produces a `.sig.json` file like this:

```json
{
  "filename": "report.pdf",
  "sha256": "7f3a91e4b82d0d8c6b3e7f9a4f1b29c8120de55a0ab781f6d92b3aa716e6f245",
  "signature": "base64-encoded RSA-PSS signature",
  "algorithm": "RSA-PSS-SHA256",
  "key_size": 2048,
  "signed_at": "2026-04-19T16:42:11+00:00"
}
```

This metadata is fully portable — it can be stored in a database, attached to an email, or checked into version control independently of the original tool.

## Cryptographic Design

- **Hash function:** SHA-256, computed over the full file contents via streamed 8 KB reads (constant memory usage regardless of file size)
- **Signature scheme:** RSA-PSS with MGF1(SHA-256) and maximum salt length — the padding scheme recommended by [NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) over legacy PKCS#1 v1.5
- **Key format:** private keys are PKCS#8 PEM (unencrypted); public keys are `SubjectPublicKeyInfo` PEM — both standard, interoperable formats
- **Key size:** RSA-2048 by default (RSA-1024 and RSA-4096 also supported)

## Project Structure

```
docverify/
├── docverify.py                  # CLI tool — all core logic
├── public_key.pem                # Sample public key (for demo/reference)
├── easy.txt                      # Sample file used for sign/verify testing
├── requirements.txt              # Python dependencies
├── .vscode/
│   └── launch.json               # VS Code debug configuration
├── docs/
│   └── images/                   # Architecture diagram & CLI screenshots
├── mini_project_final_rev.pptx   # Full project report / presentation
├── README.md
└── LICENSE
```

## Testing

The tool was validated across 7 test cases covering normal operation and edge cases:

- ✅ Normal sign + verify → returns `VERIFIED` with matching hash and valid signature
- ✅ Tamper detection → a single-character change correctly returns `FAILED` with a hash mismatch
- ✅ Wrong-key verification → correctly rejected as an invalid signature
- ✅ Empty files (0 bytes) → handled without errors
- ✅ Large files (100+ MB) → handled without errors via streamed hashing

All 7 cases passed, confirming reliable tamper detection, signature authentication, and edge-case handling.

## Roadmap

- [ ] ECDSA support as a faster, smaller alternative to RSA
- [ ] Batch signing/verification for multiple files in one command
- [ ] Trusted timestamping (RFC 3161) to prove document existence at a point in time
- [ ] GUI front-end for non-technical users
- [ ] Optional blockchain-anchored audit trail

## Tech Stack

- **Language:** Python 3.10+
- **Cryptography:** [`pyca/cryptography`](https://cryptography.io/) — RSA key generation, SHA-256 hashing, RSA-PSS signing/verification
- **CLI:** Python's built-in `argparse`

## License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute.
