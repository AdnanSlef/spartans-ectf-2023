#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the fob
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition, and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import json
import argparse
from pathlib import Path
import struct
import Crypto.PublicKey.ECC as ecc
from Crypto.Util.number import long_to_bytes

ECC_PRIVSIZE = 32
ECC_SIGNATURE_SIZE = 64

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    paired = 0x20202020 if args.paired else 0xFFFFFFFF
    pin = args.pair_pin

    # Open the secret file if it exists
    secret_file = Path(args.secret_file)
    if secret_file.exists():
        with open(secret_file, "r") as fp:
            secrets = json.load(fp)
    elif args.paired:
            raise Exception("Secrets file not found in directory, should already exist before building paired fob")
    
    if args.paired:
        # secrets[args.car_id] should be defined
        car_privkey_pem = secrets[args.car_id]["privkey_pem"]
        car_privkey = ecc.import_key(car_privkey_pem)
        car_privkey_bytes = long_to_bytes(car_privkey.d, ECC_PRIVSIZE)
    else:
        car_privkey_bytes = b"\xFF" * ECC_PRIVSIZE
    
    package_data = b"\xFF" * ECC_SIGNATURE_SIZE * 3

    eeprom_data = struct.pack(
        f"ii{'i' * ECC_PRIVSIZE}{'i' * ECC_SIGNATURE_SIZE * 3}",
        paired,
        pin,
        *car_privkey_bytes,
        *package_data
    )

    eeprom_path = args.secrets_dir / f"pfob_{args.car_id}_eeprom"

    with open(eeprom_path, "wb") as fp:
        fp.write(eeprom_data)

    if args.paired:
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define OG_PFOB 1\n")
            fp.write("#define OG_UFOB 0\n")
            fp.write("#endif\n")
    else:
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define OG_PFOB 0\n")
            fp.write("#define OG_UFOB 1\n")
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
