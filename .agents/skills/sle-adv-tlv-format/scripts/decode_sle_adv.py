#!/usr/bin/env python3
"""Decode SLE (星闪) announce / scan-response TLV bytes.

On-air layout: [type][length][value...], where `length` is the number of VALUE
bytes (the type byte is NOT counted, and it is NOT len(value)+1). A length that
overruns the buffer is the classic off-by-one that makes a scanner ignore the
device while every device-side API still returns success.

Usage:
    python3 decode_sle_adv.py "01 01 01 02 01 00"
    python3 decode_sle_adv.py 0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
    python3 decode_sle_adv.py 010101020100
    echo "0x01 0x02 0x01" | python3 decode_sle_adv.py
"""
import re
import sys

TYPES = {
    0x01: "DISCOVERY_LEVEL(发现等级)",
    0x02: "ACCESS_MODE(接入层能力)",
    0x03: "SERVICE_DATA_16BIT_UUID(标准服务数据)",
    0x04: "SERVICE_DATA_128BIT_UUID(自定义服务数据)",
    0x05: "COMPLETE_LIST_OF_16BIT_SERVICE_UUIDS",
    0x06: "COMPLETE_LIST_OF_128BIT_SERVICE_UUIDS",
    0x07: "INCOMPLETE_LIST_OF_16BIT_SERVICE_UUIDS",
    0x08: "INCOMPLETE_LIST_OF_128BIT_SERVICE_UUIDS",
    0x09: "SERVICE_STRUCTURE_HASH_VALUE",
    0x0A: "SHORTENED_LOCAL_NAME(缩写名称)",
    0x0B: "COMPLETE_LOCAL_NAME(完整名称)",
    0x0C: "TX_POWER_LEVEL(发送功率)",
    0x0D: "SLB_COMMUNICATION_DOMAIN",
    0x0E: "SLB_MEDIA_ACCESS_LAYER_ID",
    0xFE: "EXTENDED(扩展)",
    0xFF: "MANUFACTURER_SPECIFIC_DATA(厂商自定义)",
}


def parse_hex(text):
    """Accept '0x01 0x02', '01 02', '01,02', or contiguous '0102'."""
    tokens = re.findall(r"0[xX][0-9a-fA-F]{2}|[0-9a-fA-F]{2}", text)
    if tokens:
        return bytes(int(t, 16) for t in tokens)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) % 2:
        raise ValueError("odd number of hex digits")
    return bytes(int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2))


def decode(data):
    i, n = 0, len(data)
    print(f"input: {n} bytes: {' '.join(f'{b:02x}' for b in data)}")
    ok = True
    # types whose value is always exactly one byte; a different length is a red flag
    fixed_len_one = {0x01, 0x02, 0x0C}
    while i < n:
        if i + 1 >= n:
            print(f"  offset {i}: trailing lone byte 0x{data[i]:02x} "
                  f"(truncated TLV)  <-- MALFORMED")
            ok = False
            break
        type_ = data[i]
        length = data[i + 1]
        end = i + 2 + length
        name = TYPES.get(type_, "UNKNOWN")
        if end > n:
            print(f"  offset {i}: type=0x{type_:02x} ({name}) length={length} "
                  f"needs {end} bytes but buffer has {n}  <-- LENGTH OVERRUNS "
                  f"(off-by-one?)")
            print(f"      value would consume: "
                  f"{' '.join(f'{b:02x}' for b in data[i + 2:])} "
                  f"({n - i - 2} byte(s) available)")
            ok = False
            break
        value = data[i + 2:end]
        print(f"  offset {i}: type=0x{type_:02x} ({name}) length={length} "
              f"value={' '.join(f'{b:02x}' for b in value)}")
        if type_ in fixed_len_one and length != 1:
            print(f"      WARNING: type 0x{type_:02x} must have length=1, got "
                  f"{length} (length includes the type byte?)")
            ok = False
        if length == 0:
            print("      WARNING: zero-length TLV (usually a parse desync)")
            ok = False
        if type_ not in TYPES:
            print(f"      WARNING: unknown type 0x{type_:02x} (desync?)")
            ok = False
        if type_ == 0x0B and value:
            if all(0x20 <= b < 0x7F for b in value):
                print(f"      name = {value.decode('ascii')!r}")
            else:
                print("      WARNING: COMPLETE_LOCAL_NAME value is not printable")
                ok = False
        i = end
    print("RESULT:", "OK" if (ok and i == n) else "SUSPECT/MALFORMED")
    return 0 if (ok and i == n) else 1


def main():
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    try:
        data = parse_hex(text)
    except ValueError as exc:
        print(f"parse error: {exc}", file=sys.stderr)
        return 2
    return decode(data)


if __name__ == "__main__":
    sys.exit(main())
