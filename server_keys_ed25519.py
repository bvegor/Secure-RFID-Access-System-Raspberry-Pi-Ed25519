#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SK_PATH = "server_sk_ed25519.pem"
PK_PATH = "server_pk_ed25519.pem"


def main():
    if os.path.exists(SK_PATH) and os.path.exists(PK_PATH):
        print("Clés déjà présentes.")
        return

    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()

    with open(SK_PATH, "wb") as f:
        f.write(
            sk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PK_PATH, "wb") as f:
        f.write(
            pk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Clés générées dans", SK_PATH, "et", PK_PATH)


if __name__ == "__main__":
    main()
