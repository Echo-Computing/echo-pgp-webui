#!/usr/bin/env python3
"""
Generate self-signed CA + server certificates for PGP Vault HTTPS.

Run once before first launch, or after deleting pgpvault.crt / pgpvault.key:
    python tools/generate-cert.py

Certificates are written to PGP_DIR (the directory containing pgp_webui.py),
or to the current working directory if PGP_DIR is not set.

The CA cert (pgpvault-ca.crt) is what mobile clients need to install
as a trusted CA on Android. Download it from the Settings page in the
web UI, or copy it manually from PGP_DIR/pgpvault-ca.crt.
"""
import os
import sys
import subprocess
from pathlib import Path

CERT_VARS = {
    "CA_C": "US",
    "CA_ST": "State",
    "CA_L": "City",
    "CA_O": "PGP Vault",
    "CA_CN": "PGP Vault CA",
    "SV_C": "US",
    "SV_ST": "State",
    "SV_L": "City",
    "SV_O": "PGP Vault",
    "SV_CN": "localhost",
}


def run_openssl(cmd: list[str], env: dict | None = None) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR running: {' '.join(cmd)}")
        print(result.stderr)
        sys.exit(1)


def main():
    # Determine output directory
    script_dir = Path(__file__).parent.resolve()
    repo_dir = script_dir.parent
    out_dir = Path(os.environ.get("PGP_DIR", str(repo_dir)))

    ca_key = out_dir / "pgpvault-ca.key"
    ca_cert = out_dir / "pgpvault-ca.crt"
    sv_key = out_dir / "pgpvault.key"
    sv_req = out_dir / "pgpvault.csr"
    sv_cert = out_dir / "pgpvault.crt"

    print(f"Output directory: {out_dir}")

    # Step 1: CA private key
    print("[1/5] Generating CA private key...")
    run_openssl([
        "openssl", "genrsa", "-aes256",
        "-out", str(ca_key), "-passout", "pass:pgpvault",
        "2048"
    ])

    # Step 2: CA self-signed certificate
    print("[2/5] Generating CA certificate...")
    run_openssl([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key), "-sha256",
        "-out", str(ca_cert), "-days", "3650",
        "-subj", f"/C={CERT_VARS['CA_C']}/ST={CERT_VARS['CA_ST']}/L={CERT_VARS['CA_L']}/O={CERT_VARS['CA_O']}/CN={CERT_VARS['CA_CN']}",
        "-passin", "pass:pgpvault"
    ])

    # Step 3: Server private key
    print("[3/5] Generating server private key...")
    run_openssl([
        "openssl", "genrsa", "-out", str(sv_key), "2048"
    ])

    # Step 4: Server CSR
    print("[4/5] Generating server CSR...")
    run_openssl([
        "openssl", "req", "-new",
        "-key", str(sv_key),
        "-out", str(sv_req),
        "-subj", f"/C={CERT_VARS['SV_C']}/ST={CERT_VARS['SV_ST']}/L={CERT_VARS['SV_L']}/O={CERT_VARS['SV_O']}/CN={CERT_VARS['SV_CN']}"
    ])

    # Step 5: Server certificate signed by CA
    print("[5/5] Signing server certificate with CA...")
    # Create minimal CA extensions file for Windows compatibility
    ext_file = out_dir / "pgpvault.ext"
    ext_file.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0\n"
    )
    run_openssl([
        "openssl", "x509", "-req",
        "-in", str(sv_req),
        "-CA", str(ca_cert), "-CAkey", str(ca_key),
        "-out", str(sv_cert), "-days", "3650",
        "-sha256", "-extfile", str(ext_file),
        "-passin", "pass:pgpvault"
    ])
    ext_file.unlink()
    sv_req.unlink()

    # Ensure key is readable (required for TLS)
    os.chmod(sv_key, 0o600)

    print("\nDone! Generated:")
    print(f"  CA cert:  {ca_cert}  (install on Android as trusted CA)")
    print(f"  CA key:   {ca_key}   (keep private)")
    print(f"  Server:   {sv_cert}")
    print(f"  Server:   {sv_key}   (keep private)")
    print()
    print("Start the server: python pgp_webui.py")
    print("Open: https://localhost:8765")


if __name__ == "__main__":
    main()
