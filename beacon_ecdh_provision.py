"""
Beacon ECDH Provisioner
1. Connects to iBKS Plus
2. Reads beacon's 32-byte public ECDH key (a3c87508)
3. Writes it back as ADV Slot Data: [0x30][32-byte key][rotation_exp]
4. Reads back identity key (a3c87509)
5. Prints identity_key + base_time_unix for DB

Usage:
    python3 scripts/beacon_ecdh_provision.py
    python3 scripts/beacon_ecdh_provision.py --rotation-exp 10
"""

import asyncio
import argparse
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from bleak import BleakScanner, BleakClient

EDDYSTONE_SERVICE  = "a3c87500-8ed3-4bdf-8a39-a01bebede295"
LOCK_STATE         = "a3c87506-8ed3-4bdf-8a39-a01bebede295"
UNLOCK             = "a3c87507-8ed3-4bdf-8a39-a01bebede295"
ACTIVE_SLOT        = "a3c87502-8ed3-4bdf-8a39-a01bebede295"
PUBLIC_ECDH_KEY    = "a3c87508-8ed3-4bdf-8a39-a01bebede295"
EID_IDENTITY_KEY   = "a3c87509-8ed3-4bdf-8a39-a01bebede295"
ADV_SLOT_DATA      = "a3c8750a-8ed3-4bdf-8a39-a01bebede295"
REMAIN_CONNECTABLE = "a3c8750c-8ed3-4bdf-8a39-a01bebede295"

CONNECT_TIMEOUT = 20
STATE = {0x00: "Locked (disallowed)", 0x01: "Locked (send key)", 0x02: "Unlocked ✓"}


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB())
    return c.decryptor().update(data)


async def _provision(client: BleakClient, rotation_exp: int, lock_key: bytes) -> bool:

    # ── Remain Connectable ON ─────────────────────────────────────────
    try:
        await client.write_gatt_char(REMAIN_CONNECTABLE, bytes([0x01]))
        print("  Remain Connectable : ON")
    except Exception as e:
        print(f"  Warning: {e}")

    # ── Unlock ────────────────────────────────────────────────────────
    lock = await client.read_gatt_char(LOCK_STATE)
    print(f"  Lock state         : 0x{lock[0]:02X} → {STATE.get(lock[0], 'Unknown')}")

    if lock[0] == 0x00:
        print("  Unlock disallowed — cannot proceed.")
        return False
    elif lock[0] == 0x01:
        await client.write_gatt_char(UNLOCK, lock_key)
        lock = await client.read_gatt_char(LOCK_STATE)
        if lock[0] != 0x02:
            print(f"  Unlock failed (state 0x{lock[0]:02X})")
            return False
        print("  Unlocked.")

    # ── Select slot 0 ────────────────────────────────────────────────
    await client.write_gatt_char(ACTIVE_SLOT, bytes([0x00]))
    print("  Active slot        : 0")

    # ── Read beacon's public ECDH key ─────────────────────────────────
    ecdh_key = await client.read_gatt_char(PUBLIC_ECDH_KEY)
    print(f"\n  Public ECDH Key    : {ecdh_key.hex().upper()}")

    if len(ecdh_key) != 32:
        print(f"  ERROR: expected 32 bytes, got {len(ecdh_key)}")
        return False

    # ── Build and write ADV Slot Data: [0x30][32-byte ECDH key][rotation_exp]
    payload = bytes([0x30]) + bytes(ecdh_key) + bytes([rotation_exp])
    print(f"\n  Writing ADV Slot Data ({len(payload)} bytes):")
    print(f"    {payload.hex().upper()}")
    await client.write_gatt_char(ADV_SLOT_DATA, payload)

    # ── Read back ─────────────────────────────────────────────────────
    # ADV Slot Data read format: [30][rot_exp][4-byte counter][8-byte EID]
    await asyncio.sleep(1)
    slot_data       = await client.read_gatt_char(ADV_SLOT_DATA)
    identity_key_raw = await client.read_gatt_char(EID_IDENTITY_KEY)

    print(f"\n  ADV Slot Data (raw): {slot_data.hex().upper()}")

    # Parse counter from slot data: bytes 2-5
    counter = 0
    if len(slot_data) >= 6:
        counter = struct.unpack(">I", slot_data[2:6])[0]
        current_eid = slot_data[6:14].hex().upper() if len(slot_data) >= 14 else "n/a"
    else:
        current_eid = "n/a"

    # base_time = now - counter
    read_time      = int(time.time())
    base_time_unix = read_time - counter

    print(f"  Counter            : {counter}s")
    print(f"  Current EID        : {current_eid}")

    # Decrypt identity key: AES-ECB decrypt with lock key
    actual_key = aes_ecb_decrypt(lock_key, bytes(identity_key_raw))
    print(f"\n  Identity Key (enc) : {identity_key_raw.hex().upper()}")
    print(f"  Identity Key (dec) : {actual_key.hex().upper()}  ← use this in DB")
    print(f"  base_time_unix     : {base_time_unix}  (0x{base_time_unix:08X})")
    print(f"  rotation_exp       : {rotation_exp}")

    print(f"""
{'=' * 55}
  SQL TO RUN IN DATABASE
{'=' * 55}

UPDATE beacon_eid_settings
SET archived_at = NOW()
WHERE beacon_id = <beacon_id> AND archived_at IS NULL;

INSERT INTO beacon_eid_settings (beacon_id, key, rotation_exponent, base_time_unix)
VALUES (
    <beacon_id>,
    '{actual_key.hex()}',
    {rotation_exp},
    {base_time_unix}
);""")
    return True


async def run(rotation_exp: int, lock_key: bytes, uuid: str = None):
    if not uuid:
        print("Scanning for iBKS Plus by name (30s)...\n")
        found = await BleakScanner.find_device_by_name("iBKS Plus", timeout=30)
        if found is None:
            print("  iBKS Plus not found.")
            return
        uuid = found.address
        print(f"  Found: {found.name}  UUID: {uuid}\n")

    print(f"Connecting to {uuid}...")
    try:
        async with BleakClient(uuid, timeout=CONNECT_TIMEOUT) as client:
            print("  Connected!\n")
            await _provision(client, rotation_exp, lock_key)
    except Exception as e:
        print(f"  Failed: {type(e).__name__} — {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Provision iBKS Plus via ECDH: read public key, write ADV Slot Data, return identity key"
    )
    parser.add_argument("--rotation-exp", type=int, default=10,
                        help="Rotation exponent 0-15 (default: 10 = ~17 min)")
    parser.add_argument("--lock-key", type=str, default="00" * 16,
                        help="Beacon lock key (32 hex chars, default: all zeros)")
    parser.add_argument("--uuid",     type=str, default=None,
                        help="Device UUID for direct connection (skip scan)")
    args = parser.parse_args()

    if not 0 <= args.rotation_exp <= 15:
        print("ERROR: --rotation-exp must be between 0 and 15")
        return

    if len(args.lock_key) != 32:
        print("ERROR: --lock-key must be 32 hex characters")
        return

    asyncio.run(run(args.rotation_exp, bytes.fromhex(args.lock_key), args.uuid))


if __name__ == "__main__":
    main()
