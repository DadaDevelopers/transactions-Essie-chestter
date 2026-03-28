import struct

def read_varint(data, offset):
    prefix = data[offset]

    if prefix < 0xfd:
        return prefix, offset + 1
    elif prefix == 0xfd:
        value = struct.unpack("<H", data[offset+1:offset+3])[0]
        return value, offset + 3
    elif prefix == 0xfe:
        value = struct.unpack("<I", data[offset+1:offset+5])[0]
        return value, offset + 5
    else:
        value = struct.unpack("<Q", data[offset+1:offset+9])[0]
        return value, offset + 9


def decode_transaction(hex_string):

    data = bytes.fromhex(hex_string)
    offset = 0
    tx = {}

    # Version
    tx["version"] = struct.unpack("<I", data[offset:offset+4])[0]
    offset += 4

    # SegWit marker and flag
    marker = data[offset]
    flag = data[offset+1]

    tx["marker"] = format(marker, '02x')
    tx["flag"] = format(flag, '02x')

    offset += 2

    # Input count
    input_count, offset = read_varint(data, offset)
    inputs = []

    for _ in range(input_count):

        txid = data[offset:offset+32][::-1].hex()
        offset += 32

        vout = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4

        script_len, offset = read_varint(data, offset)
        script_sig = data[offset:offset+script_len].hex()

        offset += script_len

        sequence = data[offset:offset+4].hex()
        offset += 4

        inputs.append({
            "txid": txid,
            "vout": vout,
            "scriptSig": script_sig,
            "sequence": sequence
        })

    tx["inputs"] = inputs

    # Outputs
    output_count, offset = read_varint(data, offset)
    outputs = []

    for _ in range(output_count):

        amount = struct.unpack("<Q", data[offset:offset+8])[0]
        offset += 8

        script_len, offset = read_varint(data, offset)
        script_pubkey = data[offset:offset+script_len].hex()

        offset += script_len

        outputs.append({
            "amount": amount,
            "scriptPubKey": script_pubkey
        })

    tx["outputs"] = outputs

    # Witness data
    witnesses = []

    for _ in range(input_count):

        item_count, offset = read_varint(data, offset)
        items = []

        for _ in range(item_count):

            size, offset = read_varint(data, offset)
            item = data[offset:offset+size].hex()

            offset += size
            items.append(item)

        witnesses.append(items)

    tx["witness"] = witnesses

    # Locktime
    tx["locktime"] = struct.unpack("<I", data[offset:offset+4])[0]

    return tx


tx_hex = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00"

decoded = decode_transaction(tx_hex)

print(decoded)
