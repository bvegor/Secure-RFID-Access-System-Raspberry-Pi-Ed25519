#!/usr/bin/env python3

import time

import RPi.GPIO as GPIO
from mfrc522 import MFRC522

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from payload_common import SLOT_DURATION_SECONDS, parse_payload

DATA_BLOCKS = [4, 5, 6, 8, 9]
MIFARE_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
DOOR_ROOM_NUMBER = 101


def load_server_public_key(path: str) -> ed25519.Ed25519PublicKey:
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Clé publique Ed25519 attendue.")
    return key


def main():
    print("=== Mode serrure (vérification signature Ed25519) ===")
    print(f"Cette porte correspond à la chambre {DOOR_ROOM_NUMBER}.\n")

    pk_srv = load_server_public_key("server_pk_ed25519.pem")
    reader = MFRC522()

    try:
        while True:
            print("Présentez un badge sur le lecteur (Ctrl+C pour quitter)...")

            while True:
                status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
                if status == reader.MI_OK:
                    break
                time.sleep(0.1)

            status, uid = reader.MFRC522_Anticoll()
            if status != reader.MI_OK:
                print("Impossible de lire l'UID du badge.\n")
                time.sleep(1)
                continue

            reader.MFRC522_SelectTag(uid)

            all_bytes = b""
            auth_failed = False

            for block_addr in DATA_BLOCKS:
                status = reader.MFRC522_Auth(
                    reader.PICC_AUTHENT1A,
                    block_addr,
                    MIFARE_KEY,
                    uid,
                )
                if status != reader.MI_OK:
                    print(f"Erreur d'authentification sur le bloc {block_addr}.")
                    reader.MFRC522_StopCrypto1()
                    print("Accès refusé.\n")
                    auth_failed = True
                    break

                data = reader.MFRC522_Read(block_addr)
                if not data or len(data) != 16:
                    print(f"Lecture invalide sur le bloc {block_addr}.")
                    reader.MFRC522_StopCrypto1()
                    print("Accès refusé.\n")
                    auth_failed = True
                    break

                all_bytes += bytes(data)

            if auth_failed:
                time.sleep(1)
                continue

            reader.MFRC522_StopCrypto1()

            if len(all_bytes) < 80:
                print(f"Données trop courtes ({len(all_bytes)} octets).")
                print("Accès refusé.\n")
                time.sleep(1)
                continue

            badge_data = all_bytes[:80]
            payload = badge_data[:16]
            signature = badge_data[16:80]

            try:
                pk_srv.verify(signature, payload)
            except InvalidSignature:
                print("Signature invalide.")
                print("Accès refusé.\n")
                time.sleep(1)
                continue

            try:
                rights = parse_payload(payload)
            except Exception as e:
                print(f"Erreur de parsing du payload : {e}")
                print("Accès refusé.\n")
                time.sleep(1)
                continue

            now = int(time.time())
            current_slot = now // SLOT_DURATION_SECONDS

            room = rights["room_number"]
            start_slot = rights["start_slot"]
            duration_slots = rights["duration_slots"]
            end_slot = start_slot + duration_slots

            if room != DOOR_ROOM_NUMBER:
                print("Le numéro de chambre ne correspond pas à cette porte.")
                print("Accès refusé.\n")
                time.sleep(1)
                continue

            if not (start_slot <= current_slot < end_slot):
                print("Badge hors période de validité.")
                print("Accès refusé.\n")
                time.sleep(1)
                continue

            print(f"Badge valide pour la chambre {room}.")
            print("Porte ouverte.\n")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nArrêt demandé.")
    finally:
        GPIO.cleanup()


if __name__ == "__main__":
    main()
