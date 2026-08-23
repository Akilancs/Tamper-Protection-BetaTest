#!/usr/bin/env python3


import argparse
import hashlib
import json
import base64
import os
import sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: 'cryptography' library not found.")
    print("Install it with:  pip install cryptography")
    sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CORE ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def hash_file(filepath):
    """Stream-hash a file in 8 KB chunks. Returns hex SHA-256 digest."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_keys(key_size=2048):
    """Generate RSA key pair. Returns (private_key, public_key) objects."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key(public_key, path):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_file(filepath, private_key):
    """Sign a file. Returns signature metadata dict."""
    with open(filepath, "rb") as f:
        data = f.read()

    doc_hash = hashlib.sha256(data).hexdigest()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return {
        "filename": os.path.basename(filepath),
        "sha256": doc_hash,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "algorithm": "RSA-PSS-SHA256",
        "key_size": private_key.key_size,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_file(filepath, sig_meta, public_key):
    """Verify a file against signature metadata. Returns result dict."""
    with open(filepath, "rb") as f:
        data = f.read()

    current_hash = hashlib.sha256(data).hexdigest()
    hash_ok = current_hash == sig_meta["sha256"]

    sig_bytes = base64.b64decode(sig_meta["signature"])
    sig_ok = False
    try:
        public_key.verify(
            sig_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        sig_ok = True
    except InvalidSignature:
        sig_ok = False

    return {
        "filename": sig_meta["filename"],
        "hash_match": hash_ok,
        "signature_valid": sig_ok,
        "verified": hash_ok and sig_ok,
        "original_hash": sig_meta["sha256"],
        "current_hash": current_hash,
        "algorithm": sig_meta.get("algorithm", "unknown"),
        "signed_at": sig_meta.get("signed_at", "unknown"),
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI COMMANDS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def cmd_generate_keys(args):
    """Handle 'generate-keys' subcommand."""
    priv_path = args.private_key
    pub_path = args.public_key
    bits = args.bits

    if os.path.exists(priv_path) and not args.force:
        print(f"ERROR: '{priv_path}' already exists. Use --force to overwrite.")
        sys.exit(1)
    if os.path.exists(pub_path) and not args.force:
        print(f"ERROR: '{pub_path}' already exists. Use --force to overwrite.")
        sys.exit(1)

    print(f"Generating RSA-{bits} key pair...")
    private_key, public_key = generate_keys(bits)
    save_private_key(private_key, priv_path)
    save_public_key(public_key, pub_path)

    print()
    print(f"  Private key : {priv_path}")
    print(f"  Public key  : {pub_path}")
    print(f"  Key size    : {bits} bits")
    print()
    print("IMPORTANT: Keep your private key secret.")
    print("           Share only the public key for verification.")


def cmd_sign(args):
    """Handle 'sign' subcommand."""
    filepath = args.file
    key_path = args.key
    output = args.output

    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    if not os.path.isfile(key_path):
        print(f"ERROR: Private key not found: {key_path}")
        sys.exit(1)

    # Default output path
    if output is None:
        output = filepath + ".sig.json"

    print(f"Signing: {filepath}")
    print(f"Key    : {key_path}")
    print()

    # Hash first (stream-based for display)
    doc_hash = hash_file(filepath)
    print(f"  SHA-256 : {doc_hash}")

    # Load key and sign
    private_key = load_private_key(key_path)
    sig_meta = sign_file(filepath, private_key)

    # Write signature metadata
    with open(output, "w") as f:
        json.dump(sig_meta, f, indent=2)

    file_size = os.path.getsize(filepath)
    print(f"  Algorithm : {sig_meta['algorithm']}")
    print(f"  Key size  : {sig_meta['key_size']} bits")
    print(f"  File size : {format_size(file_size)}")
    print(f"  Signed at : {sig_meta['signed_at']}")
    print()
    print(f"  Signature saved -> {output}")


def cmd_verify(args):
    """Handle 'verify' subcommand."""
    filepath = args.file
    sig_path = args.sig
    key_path = args.key

    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    # Auto-detect signature file
    if sig_path is None:
        sig_path = filepath + ".sig.json"
    if not os.path.isfile(sig_path):
        print(f"ERROR: Signature file not found: {sig_path}")
        print(f"       Expected at: {filepath}.sig.json")
        print(f"       Or specify with: --sig <path>")
        sys.exit(1)

    if not os.path.isfile(key_path):
        print(f"ERROR: Public key not found: {key_path}")
        sys.exit(1)

    # Load signature metadata
    with open(sig_path, "r") as f:
        sig_meta = json.load(f)

    # Load public key
    public_key = load_public_key(key_path)

    print(f"Verifying: {filepath}")
    print(f"Signature: {sig_path}")
    print(f"Key      : {key_path}")
    print()

    # Verify
    result = verify_file(filepath, sig_meta, public_key)

    # Display results
    print("  ┌─────────────────────────────────────────┐")
    if result["verified"]:
        print("  │         ✅  VERIFIED                    │")
    else:
        print("  │         ❌  VERIFICATION FAILED          │")
    print("  └─────────────────────────────────────────┘")
    print()
    print(f"  Hash match      : {'Yes' if result['hash_match'] else 'NO — MISMATCH'}")
    print(f"  Signature valid : {'Yes' if result['signature_valid'] else 'NO — INVALID'}")
    print(f"  Algorithm       : {result['algorithm']}")
    print(f"  Signed at       : {result['signed_at']}")
    print(f"  Verified at     : {result['verified_at']}")

    if not result["hash_match"]:
        print()
        print("  HASH DIAGNOSTIC:")
        print(f"    Original : {result['original_hash']}")
        print(f"    Current  : {result['current_hash']}")
        print()
        print("  The document has been MODIFIED since it was signed.")

    if not result["signature_valid"] and result["hash_match"]:
        print()
        print("  SIGNATURE DIAGNOSTIC:")
        print("    The hash matches but the signature is invalid.")
        print("    This likely means the wrong public key was used.")

    # Exit code: 0 = verified, 1 = failed
    sys.exit(0 if result["verified"] else 1)


def cmd_hash(args):
    """Handle 'hash' subcommand (utility)."""
    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    digest = hash_file(filepath)
    if args.quiet:
        print(digest)
    else:
        print(f"SHA-256 ({os.path.basename(filepath)}) = {digest}")


def cmd_inspect(args):
    """Handle 'inspect' subcommand — read a .sig.json file."""
    sig_path = args.sig
    if not os.path.isfile(sig_path):
        print(f"ERROR: Signature file not found: {sig_path}")
        sys.exit(1)

    with open(sig_path, "r") as f:
        sig_meta = json.load(f)

    print(f"Signature Metadata: {sig_path}")
    print()
    print(f"  Filename  : {sig_meta.get('filename', 'N/A')}")
    print(f"  SHA-256   : {sig_meta.get('sha256', 'N/A')}")
    print(f"  Algorithm : {sig_meta.get('algorithm', 'N/A')}")
    print(f"  Key size  : {sig_meta.get('key_size', 'N/A')} bits")
    print(f"  Signed at : {sig_meta.get('signed_at', 'N/A')}")
    print(f"  Signature : {sig_meta.get('signature', 'N/A')[:48]}...")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def format_size(nbytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ARGUMENT PARSER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_parser():
    parser = argparse.ArgumentParser(
        prog="docverify",
        description="Document Integrity Verification using SHA-256 and RSA-PSS Digital Signatures",
        epilog="Examples:\n"
               "  docverify generate-keys\n"
               "  docverify sign   report.pdf --key private_key.pem\n"
               "  docverify verify report.pdf --key public_key.pem\n"
               "  docverify hash   report.pdf\n"
               "  docverify inspect report.pdf.sig.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="docverify 1.0.0")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── generate-keys ──
    gk = sub.add_parser("generate-keys", help="Generate RSA key pair",
                         description="Generate an RSA-2048 (or custom size) key pair and save to PEM files.")
    gk.add_argument("--private-key", default="private_key.pem",
                     help="Output path for private key (default: private_key.pem)")
    gk.add_argument("--public-key", default="public_key.pem",
                     help="Output path for public key (default: public_key.pem)")
    gk.add_argument("--bits", type=int, default=2048, choices=[1024, 2048, 4096],
                     help="RSA key size in bits (default: 2048)")
    gk.add_argument("--force", action="store_true",
                     help="Overwrite existing key files")

    # ── sign ──
    sg = sub.add_parser("sign", help="Sign a document",
                         description="Compute SHA-256 hash and sign with RSA-PSS. "
                                     "Outputs a .sig.json metadata file.")
    sg.add_argument("file", help="Path to the document to sign")
    sg.add_argument("--key", default="private_key.pem",
                     help="Path to private key PEM file (default: private_key.pem)")
    sg.add_argument("--output", "-o", default=None,
                     help="Output path for signature file (default: <file>.sig.json)")

    # ── verify ──
    vf = sub.add_parser("verify", help="Verify a signed document",
                          description="Verify a document against its .sig.json signature metadata "
                                      "using the signer's public key.")
    vf.add_argument("file", help="Path to the document to verify")
    vf.add_argument("--key", default="public_key.pem",
                     help="Path to public key PEM file (default: public_key.pem)")
    vf.add_argument("--sig", default=None,
                     help="Path to .sig.json file (default: <file>.sig.json)")

    # ── hash ──
    hs = sub.add_parser("hash", help="Compute SHA-256 hash of a file",
                          description="Compute and display the SHA-256 digest of a file.")
    hs.add_argument("file", help="Path to the file to hash")
    hs.add_argument("--quiet", "-q", action="store_true",
                     help="Print only the hash (no filename)")

    # ── inspect ──
    ins = sub.add_parser("inspect", help="Inspect a .sig.json file",
                          description="Display the contents of a signature metadata file.")
    ins.add_argument("sig", help="Path to the .sig.json file")

    return parser


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "generate-keys": cmd_generate_keys,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "hash": cmd_hash,
        "inspect": cmd_inspect,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
