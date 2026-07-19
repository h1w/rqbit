#!/usr/bin/env python3
"""Generate x25519 keypairs and pairing bundle for rqbit tunnel.

Usage:
    python3 scripts/rqbit-tunnel-keygen.py [--output-dir DIR]

Outputs:
    client.key       — 32-byte x25519 private key (hex-encoded)
    client.pub       — 32-byte x25519 public key (hex-encoded)
    server.key       — 32-byte x25519 private key (hex-encoded)
    server.pub       — 32-byte x25519 public key (hex-encoded)

Permissions:
    *.key files are created with mode 0o600 (owner read/write only).
    *.pub files are world-readable.

Dependencies:
    pip install cryptography
"""

import argparse
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError:
    print("ERROR: cryptography package not found. Install with: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)


def generate_keypair(name: str, out_dir: Path):
    """Generate an x25519 keypair and write hex-encoded files."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes_raw()  # 32 bytes
    pub_bytes = public_key.public_bytes_raw()      # 32 bytes

    priv_hex = priv_bytes.hex()
    pub_hex = pub_bytes.hex()

    priv_path = out_dir / f"{name}.key"
    pub_path = out_dir / f"{name}.pub"

    # Write private key with restricted permissions
    with open(priv_path, "w") as f:
        f.write(priv_hex + "\n")
    os.chmod(priv_path, 0o600)

    # Write public key world-readable
    with open(pub_path, "w") as f:
        f.write(pub_hex + "\n")

    print(f"  {priv_path}  (mode 600)")
    print(f"  {pub_path}")

    return priv_hex, pub_hex


def main():
    parser = argparse.ArgumentParser(
        description="Generate x25519 keypairs for rqbit tunnel"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        help="Output directory (default: current directory)",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating rqbit tunnel keys...\n")

    print("[client keypair]")
    client_priv, client_pub = generate_keypair("client", out_dir)

    print("\n[server keypair]")
    server_priv, server_pub = generate_keypair("server", out_dir)

    print(f"""
Done! Files written to {out_dir.absolute()}/

  Client identity (private):  client.key   — keep secret, never share
  Client public:              client.pub   — safe to share with server admin
  Server identity (private):  server.key   — keep secret, never share
  Server public:              server.pub   — give to client

Server deployment:
  rqbit server start /data \\
    --tunnel-mode server \\
    --tunnel-peer-listen 0.0.0.0:4242 \\
    --tunnel-server-key /path/to/server.key \\
    --tunnel-allowed-clients /path/to/allowed-clients.txt \\
    --tunnel-carrier-root /var/lib/rqbit/tunnel

  # allowed-clients.txt contains one hex-encoded client public key per line:
  #   echo "{client_pub}" > allowed-clients.txt

Client deployment:
  rqbit server start /data \\
    --tunnel-mode client \\
    --tunnel-socks-listen 127.0.0.1:1080 \\
    --tunnel-server-addr vps.example.com:4242 \\
    --tunnel-client-key /path/to/client.key \\
    --tunnel-server-key /path/to/server.pub

  # Point your browser or application at SOCKS5 proxy:
  #   curl --socks5 127.0.0.1:1080 https://checkip.amazonaws.com
""")


if __name__ == "__main__":
    main()