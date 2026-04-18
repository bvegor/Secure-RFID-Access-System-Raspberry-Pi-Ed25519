#!/usr/bin/env python3

import time

import RPi.GPIO as GPIO
from mfrc522 import MFRC522

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from payload_common import SLOT_DURATION_SECONDS, build_payload

DATA_BLOCKS = [4, 5, 6, 8, 9]
MIFARE_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]


def load_server_private_key(path: str) -> ed25519.Ed25519PrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Clé privée Ed25519 attendue.")
    return key


def split_in_chunks(data: bytes, size: int):
    return [data[i : i + size] for i in range(0, len(data), size)]


def main():
    print("=== Création de badge (signature Ed25519) ===")

    room_str = input("Numéro de chambre : ").strip()
    duration_str = input("Durée de validité (minutes) : ").strip()

    try:
        room_number = int(room_str)
        duration_min = int(duration_str)
    except ValueError:
        print("Valeurs invalides.")
        return

    now = int(time.time())
    start_slot = now // SLOT_DURATION_SECONDS
    duration_slots = max(1, (duration_min * 60) // SLOT_DURATION_SECONDS)

    payload = build_payload(
        room_number=room_number,
        start_slot=start_slot,
        duration_slots=duration_slots,
    )

    sk_srv = load_server_private_key("server_sk_ed25519.pem")
    signature = sk_srv.sign(payload)

    if len(payload) != 16 or len(signature) != 64:
        print("Taille inattendue du payload ou de la signature.")
        return

    badge_data = payload + signature
    chunks = split_in_chunks(badge_data, 16)

    if len(chunks) != 5:
        print("Erreur de découpe des données.")
        return

    reader = MFRC522()

    try:
        print("Approchez un badge MIFARE sur le lecteur...")
        while True:
            status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
            if status == reader.MI_OK:
                break
            time.sleep(0.1)

        status, uid = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            print("Impossible de lire l'UID du badge.")
            return

        reader.MFRC522_SelectTag(uid)

        for index, block_addr in enumerate(DATA_BLOCKS):
            status = reader.MFRC522_Auth(
                reader.PICC_AUTHENT1A,
                block_addr,
                MIFARE_KEY,
                uid,
            )
            if status != reader.MI_OK:
                print(f"Erreur d'authentification sur le bloc {block_addr}.")
                reader.MFRC522_StopCrypto1()
                return

            chunk = chunks[index]
            data_list = list(chunk)
            if len(data_list) < 16:
                data_list += [0] * (16 - len(data_list))

            reader.MFRC522_Write(block_addr, data_list)

        reader.MFRC522_StopCrypto1()
        print("Badge programmé.")

    finally:
        GPIO.cleanup()


if __name__ == "__main__":
    main()
