#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the car
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition,and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import json
import argparse
from pathlib import Path
import Crypto.PublicKey.ECC as ecc
from Crypto.Util.number import bytes_to_long, long_to_bytes

ECC_PRIVSIZE = 32
ECC_PUBSIZE = ECC_PRIVSIZE * 2

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secrets-dir", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    args = parser.parse_args()

    secret_file = args.secret_dir / "car_secrets.json"

    # Open the secret file if it exists
    if secret_file.exists():
        with open(secret_file, "r") as fp:
            secrets = json.load(fp)
    else:
        secrets = {}

    # Generate secret
    privkey = ecc.generate(curve='secp256r1')
    car_pubkey = privkey.public_key()

    privkey_pem = privkey.export_key(format="PEM")
    pubkey_pem = car_pubkey.export_key(format="PEM")

    car_secret = { "privkey_pem": privkey_pem, "pubkey_pem": pubkey_pem }
    secrets[str(args.car_id)] = car_secret

    # Save the secret file
    with open(secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)
    
    # Load host pubkey
    host_pubkey_file = args.secrets_dir / "host_pubkey.PEM"
    
    with open(host_pubkey_file) as fp:
        host_pubkey_pem = fp.read()

    host_pubkey = ecc.import_key(host_pubkey_pem)

    # Get bytes
    host_pubkey_bytes = long_to_bytes(host_pubkey._point.x, ECC_PRIVSIZE) + long_to_bytes(host_pubkey._point.y, ECC_PRIVSIZE)
    car_pubkey_bytes = long_to_bytes(car_pubkey._point.x, ECC_PRIVSIZE) + long_to_bytes(car_pubkey._point.y, ECC_PRIVSIZE)

    eeprom_data = host_pubkey_bytes + car_pubkey_bytes
    eeprom_path = args.secrets_dir / f"car_{args.car_id}_eeprom"

    with open(eeprom_path, "w") as fp:
        fp.write(eeprom_data)

    # Write to header file
    # with open(args.header_file, "w") as fp:
    #     fp.write("#ifndef __CAR_SECRETS__\n")
    #     fp.write("#define __CAR_SECRETS__\n\n")
    #     fp.write(f"#define CAR_SECRET {123}\n\n") # placeholder
    #     fp.write(f'#define CAR_ID "{args.car_id}"\n\n')
    #     fp.write('#define PASSWORD "unlock"\n\n')
    #     fp.write("#endif\n")


if __name__ == "__main__":
    main()
