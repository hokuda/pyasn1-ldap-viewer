import json
import re

from pyasn1.codec.ber.decoder import decode as ber_decoder
from pyasn1.error import PyAsn1Error
from pyasn1_ldap import rfc4511

OFFSET_RE = re.compile(r"^[0-9A-Fa-f]{4,8}:?$")
BYTE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")
MAX_BYTES_PER_LINE = 16


def extract_hex_bytes(text: str) -> bytes:
    """Pull raw bytes out of a HexDumpEncoder-style dump, ignoring the
    leading offset column and the trailing ASCII sidebar on each line."""
    out = bytearray()
    for raw_line in text.splitlines():
        tokens = raw_line.split()
        if not tokens:
            continue
        if OFFSET_RE.match(tokens[0]):
            tokens = tokens[1:]
        for tok in tokens[:MAX_BYTES_PER_LINE]:
            if BYTE_RE.match(tok):
                out.append(int(tok, 16))
            else:
                break
    return bytes(out)


def decode_ldap_messages(data: bytes) -> dict:
    """Repeatedly BER-decode LDAPMessage PDUs, since a pasted dump may
    contain more than one concatenated message."""
    messages = []
    rest = data
    error = None
    while rest:
        try:
            msg, rest = ber_decoder(rest, asn1Spec=rfc4511.LDAPMessage())
        except PyAsn1Error as exc:
            error = f"BER decode error after {len(messages)} message(s): {exc}"
            break
        messages.append(msg.prettyPrint())
    return {
        "messages": messages,
        "count": len(messages),
        "error": error,
        "leftover_bytes": len(rest) if rest else 0,
    }


def run(hex_text: str) -> str:
    try:
        data = extract_hex_bytes(hex_text)
    except Exception as exc:
        return json.dumps({"ok": False, "stage": "extract", "error": str(exc)})
    if not data:
        return json.dumps(
            {"ok": False, "stage": "extract", "error": "No hex bytes found in input."}
        )
    result = decode_ldap_messages(data)
    result.update(ok=True, byte_count=len(data))
    return json.dumps(result)
