import json
import re

from pyasn1.codec.ber.decoder import decode as ber_decoder
from pyasn1.error import PyAsn1Error
from pyasn1_ldap import rfc4511

OFFSET_RE = re.compile(r"^[0-9A-Fa-f]{4,8}:?$")
BYTE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")
MAX_BYTES_PER_LINE = 16
DIAGNOSTIC_MESSAGE_RE = re.compile(r"(diagnosticMessage=)0x([0-9A-Fa-f]+)")
FILTER_LINE_RE = re.compile(r"^(?P<indent> *)filter=")
ATTRIBUTES_LINE_RE = re.compile(r"^(?P<indent> *)attributes=AttributeSelection:$")

FILTER_COMPARISON_OPS = {
    "equalityMatch": "=",
    "greaterOrEqual": ">=",
    "lessOrEqual": "<=",
    "approxMatch": "~=",
}


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


def escape_filter_value(value: bytes) -> str:
    """Render an assertion value per RFC 4515: printable text as-is, with
    '*', '(', ')', '\\' and NUL backslash-hex-escaped; genuinely binary
    values are escaped byte-by-byte."""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return "".join("\\%02x" % b for b in value)
    out = []
    for ch in text:
        if ch in ("*", "(", ")", "\\"):
            out.append("\\%02x" % ord(ch))
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def render_filter(filt) -> str:
    """Render a decoded rfc4511.Filter as an RFC 4515 filter string, e.g.
    (&(ou=Marketing)(!(description=*X.500*)))."""
    name = filt.getName()
    component = filt.getComponent()

    if name in ("and", "or"):
        op = "&" if name == "and" else "|"
        inner = "".join(render_filter(sub) for sub in component)
        return f"({op}{inner})"

    if name == "not":
        return f"(!{render_filter(component)})"

    if name in FILTER_COMPARISON_OPS:
        attr = str(component["attributeDesc"])
        value = escape_filter_value(bytes(component["assertionValue"]))
        return f"({attr}{FILTER_COMPARISON_OPS[name]}{value})"

    if name == "substrings":
        attr = str(component["type"])
        initial = None
        final = None
        middles = []
        for choice in component["substrings"]:
            value = escape_filter_value(bytes(choice.getComponent()))
            choice_name = choice.getName()
            if choice_name == "initial":
                initial = value
            elif choice_name == "final":
                final = value
            else:
                middles.append(value)
        pieces = [initial or ""] + middles + [final or ""]
        return f"({attr}={'*'.join(pieces)})"

    if name == "present":
        return f"({str(component)}=*)"

    if name == "extensibleMatch":
        attr = str(component["type"]) if component["type"].isValue else ""
        rule = str(component["matchingRule"]) if component["matchingRule"].isValue else ""
        dn = ":dn" if bool(component["dnAttributes"]) else ""
        rule_part = f":{rule}" if rule else ""
        value = escape_filter_value(bytes(component["matchValue"]))
        return f"({attr}{dn}{rule_part}:={value})"

    return f"(unsupported-filter-type:{name})"


def _skip_block(lines: list, start: int, indent_len: int) -> int:
    """Return the index of the next line that is not part of the
    (blank-line-separated) block nested under a field at indent_len."""
    i = start
    while i < len(lines):
        rest_indent = len(lines[i]) - len(lines[i].lstrip(" "))
        if lines[i].strip() == "" or rest_indent > indent_len:
            i += 1
            continue
        break
    return i


def render_search_filter_as_string(pretty: str, filter_str: str) -> str:
    """Replace the (potentially deeply nested, multi-line) default
    prettyPrint() rendering of the 'filter=' field with a single-line
    ldapsearch-style filter string."""
    lines = pretty.split("\n")
    out = []
    i = 0
    while i < len(lines):
        match = FILTER_LINE_RE.match(lines[i])
        if not match:
            out.append(lines[i])
            i += 1
            continue

        indent = match.group("indent")
        out.append(f"{indent}filter={filter_str}")
        i = _skip_block(lines, i + 1, len(indent))
    return "\n".join(out)


def render_attributes_as_list(pretty: str, attr_names: list) -> str:
    """pyasn1's default prettyPrint() joins the requested attributes into
    a single space-separated line. List them one per line instead."""
    lines = pretty.split("\n")
    out = []
    i = 0
    while i < len(lines):
        match = ATTRIBUTES_LINE_RE.match(lines[i])
        if not match:
            out.append(lines[i])
            i += 1
            continue

        indent = match.group("indent")
        out.append(lines[i])
        i = _skip_block(lines, i + 1, len(indent))
        out.extend(f"{indent} {name}" for name in attr_names)
    return "\n".join(out)


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
        pretty = render_diagnostic_message_as_string(msg.prettyPrint())
        protocol_op = msg["protocolOp"]
        if protocol_op.getName() == "searchRequest":
            search_request = protocol_op["searchRequest"]
            try:
                filter_str = render_filter(search_request["filter"])
                pretty = render_search_filter_as_string(pretty, filter_str)
            except Exception:
                pass
            try:
                attr_names = [str(attr) for attr in search_request["attributes"]]
                pretty = render_attributes_as_list(pretty, attr_names)
            except Exception:
                pass
        messages.append(pretty)
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
