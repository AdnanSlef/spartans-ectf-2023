# Generate host secrets and store them in volume

import argparse
from pathlib import Path
import Crypto.PublicKey.ECC as ecc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-dir", type=Path, required=True)
    args = parser.parse_args()

    # Generate secrets
    privkey = ecc.generate(curve='secp256r1')

    privkey_pem = privkey.export_key(format="PEM")
    pubkey_pem = privkey.public_key().export_key(format="PEM")

    privkey_path = args.secrets_dir / "host_privkey.PEM"
    pubkey_path = args.secrets_dir / "host_pubkey.PEM"

    # Save the secret file
    with open(privkey_path, "w") as fp:
      fp.write(privkey_pem)
    
    with open(pubkey_path, "w") as fp:
      fp.write(pubkey_pem)

if __name__ == "__main__":
    main()
