import json
import re

from pyasn1.codec.ber.decoder import decode as ber_decoder
from pyasn1.error import PyAsn1Error
from pyasn1_ldap import rfc4511

OFFSET_RE = re.compile(r"^[0-9A-Fa-f]{4,8}:?$")
BYTE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")
MAX_BYTES_PER_LINE = 16
DIAGNOSTIC_MESSAGE_RE = re.compile(r"(diagnosticMessage=)0x([0-9A-Fa-f]+)")


def extract_hex_bytes(text: str) -> bytes:
    """Pull raw bytes out of a HexDumpEncoder-style dump, ignoring any
    leading log prefix (timestamp, level, thread name, ...) and offset
    column, plus the trailing ASCII sidebar on each line."""
    out = bytearray()
    for raw_line in text.splitlines():
        tokens = raw_line.split()
        if not tokens:
            continue
        start = 0
        for i, tok in enumerate(tokens):
            if OFFSET_RE.match(tok) and i + 1 < len(tokens) and BYTE_RE.match(tokens[i + 1]):
                start = i + 1
                break
        for tok in tokens[start : start + MAX_BYTES_PER_LINE]:
            if BYTE_RE.match(tok):
                out.append(int(tok, 16))
            else:
                break
    return bytes(out)


def render_diagnostic_message_as_string(pretty: str) -> str:
    """pyasn1's default OctetString.prettyPrint() falls back to a hex dump
    whenever a byte is outside the printable ASCII range, which hides
    otherwise-readable diagnosticMessage text (e.g. non-ASCII characters).
    Redecode it as UTF-8 and show the string when possible."""

    def repl(match: re.Match) -> str:
        prefix, hex_bytes = match.groups()
        try:
            decoded = bytes.fromhex(hex_bytes).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)
        return prefix + decoded

    return DIAGNOSTIC_MESSAGE_RE.sub(repl, pretty)


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
        messages.append(render_diagnostic_message_as_string(msg.prettyPrint()))
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
