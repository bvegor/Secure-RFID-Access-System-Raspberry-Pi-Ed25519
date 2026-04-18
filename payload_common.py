#!/usr/bin/env python3

import struct

SLOT_DURATION_SECONDS = 60


def build_payload(room_number: int, start_slot: int, duration_slots: int) -> bytes:
    version = 1
    reserved = b"\x00" * 7
    return struct.pack(
        "<B H I H 7s",
        version,
        room_number,
        start_slot,
        duration_slots,
        reserved,
    )


def parse_payload(payload: bytes) -> dict:
    if len(payload) != 16:
        raise ValueError("Payload de taille invalide.")
    version, room_number, start_slot, duration_slots, _ = struct.unpack(
        "<B H I H 7s", payload
    )
    return {
        "version": version,
        "room_number": room_number,
        "start_slot": start_slot,
        "duration_slots": duration_slots,
    }
