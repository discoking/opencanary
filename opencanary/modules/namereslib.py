"""Packet and matching helpers for the name-resolution canary.

OpenCanary sends LLMNR, NBT-NS, and mDNS lookups for names it owns. A reply
that claims one of those names is an alert. This module never answers anyone
else's query.
"""

import ipaddress
import socket
import struct

DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
NBT_TYPE_NB = 0x0020
MAX_PACKET_LEN = 2048
MAX_RECORDS = 64
MAX_ANSWERED_IPS = 8

PROTOCOL_LABELS = {
    "llmnr": "LLMNR",
    "nbtns": "NBT-NS",
    "mdns": "mDNS",
}


class ProtocolError(ValueError):
    """Raised when a packet cannot be parsed safely."""


def normalize_dns_name(name):
    return str(name).strip().rstrip(".").lower()


def name_matches(candidate, expected):
    normalized = normalize_dns_name(candidate)
    return any(normalized == normalize_dns_name(item) for item in expected)


def nbt_name_ok(name):
    try:
        raw = str(name).strip().encode("ascii")
    except UnicodeEncodeError:
        return False
    return 1 <= len(raw) <= 15


def mdns_query_name(name):
    clean = str(name).strip().rstrip(".")
    if "." not in clean:
        return clean + ".local"
    return clean


def expand_match_names(kind, names):
    expanded = []
    for name in names:
        expanded.append(name)
        if kind == "mdns":
            expanded.append(mdns_query_name(name))
    return expanded


def encode_dns_name(name):
    clean = str(name).strip().rstrip(".")
    if not clean:
        raise ProtocolError("DNS name must not be empty")

    wire = bytearray()
    for label in clean.split("."):
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProtocolError("non-ASCII DNS label") from exc
        if not encoded or len(encoded) > 63:
            raise ProtocolError("invalid DNS label length")
        wire.append(len(encoded))
        wire.extend(encoded)
    wire.append(0)
    if len(wire) > 255:
        raise ProtocolError("DNS name is too long")
    return bytes(wire)


def build_llmnr_query(transaction_id, name):
    header = struct.pack("!HHHHHH", transaction_id & 0xFFFF, 0, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", DNS_TYPE_A, 1)
    return header + question


def build_mdns_query(name):
    # Class IN without the QU bit. A unicast-only question is ignored by
    # some responders, and a normal multicast question looks like a client.
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", DNS_TYPE_A, 1)
    return header + question


def encode_nbt_name(name, suffix=0x20):
    if not nbt_name_ok(name):
        raise ProtocolError("invalid NetBIOS name")
    if not 0 <= suffix <= 0xFF:
        raise ProtocolError("invalid NetBIOS suffix")

    raw = str(name).strip().upper().encode("ascii").ljust(15, b" ")
    raw += bytes([suffix])
    encoded = bytearray()
    for byte in raw:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes([32]) + bytes(encoded) + b"\x00"


def build_nbtns_query(transaction_id, name, suffix=0x20):
    # 0x0110 is the broadcast query shape Windows sends.
    header = struct.pack("!HHHHHH", transaction_id & 0xFFFF, 0x0110, 1, 0, 0, 0)
    question = encode_nbt_name(name, suffix) + struct.pack("!HH", NBT_TYPE_NB, 1)
    return header + question


def parse_allowlist(entries):
    if entries is None:
        return []
    if isinstance(entries, str):
        entries = [entries]
    if not isinstance(entries, (list, tuple)):
        raise ValueError("allowlist must be a list of IPs or CIDR ranges")

    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(str(entry), strict=False))
        except ValueError as exc:
            raise ValueError("invalid allowlist entry %r" % entry) from exc
    return networks


def source_allowed(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def _config_value(config, key):
    try:
        return config.getVal(key)
    except KeyError:
        return None


def _names_from_keys(config, keys):
    for key in keys:
        value = _config_value(config, key)
        if not value:
            continue
        values = value if isinstance(value, (list, tuple)) else [value]
        names = [str(item).strip() for item in values if str(item).strip()]
        if names:
            return names
    return None


def collect_names(config, prefix, default="DC03"):
    own = _names_from_keys(config, ("%s.hostnames" % prefix, "%s.hostname" % prefix))
    if own:
        return own
    if prefix != "llmnr":
        shared = _names_from_keys(config, ("llmnr.hostnames", "llmnr.hostname"))
        if shared:
            return shared
    return [default]


def collect_number(config, keys, default, allow_zero=False):
    for key in keys:
        value = _config_value(config, key)
        if value is None:
            continue
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("%s must be a positive number" % key) from exc
        if number < 0 or (number == 0 and not allow_zero):
            raise ValueError("%s must be a positive number" % key)
        return number
    return float(default)


def collect_allowlist(config, prefix):
    entries = []
    for key in ("nameres.allowlist", "%s.allowlist" % prefix):
        value = _config_value(config, key)
        if not value:
            continue
        if isinstance(value, str):
            entries.append(value)
        elif isinstance(value, (list, tuple)):
            entries.extend(value)
        else:
            raise ValueError("%s must be a list of IPs or CIDR ranges" % key)
    return parse_allowlist(entries)


def consider_response(data, kind, names, outstanding, now):
    """Return alert fields when a packet is a reply to one of our lookups."""
    if not data or len(data) > MAX_PACKET_LEN:
        return None
    try:
        if kind == "nbtns":
            return _consider_nbtns(data, outstanding, now)
        return _consider_dns(data, kind, names, outstanding, now)
    except (ProtocolError, struct.error, IndexError, ValueError):
        return None


def _consider_dns(data, kind, names, outstanding, now):
    message = _parse_dns(data)
    if not message["response"]:
        return None

    query_name = None
    expected = names
    if kind != "mdns":
        query_name, expected = _outstanding_names(
            message["transaction_id"], outstanding, now
        )
        if query_name is None:
            return None

    matched = _matched_dns_name(message, expected)
    if matched is None:
        return None

    ips, ttl = _dns_addresses(message, matched)
    if not ips:
        return None
    return _alert(
        kind,
        query_name or matched,
        matched,
        ips,
        ttl,
        message["transaction_id"],
        message["rcode"],
    )


def _consider_nbtns(data, outstanding, now):
    message = _parse_nbtns(data)
    if not message["response"]:
        return None

    query_name, expected = _outstanding_names(
        message["transaction_id"], outstanding, now
    )
    if query_name is None:
        return None

    matched = _matched_nbt_name(message, expected)
    if matched is None:
        return None
    if not message["ips"]:
        return None
    return _alert(
        "nbtns",
        query_name,
        matched,
        message["ips"],
        message["ttl"],
        message["transaction_id"],
        message["rcode"],
        message["suffix"],
    )


def _outstanding_names(transaction_id, outstanding, now):
    entry = outstanding.get(transaction_id)
    if entry is None:
        return None, None
    query_name, expiry = entry
    if now > expiry:
        return None, None
    return query_name, [query_name]


def _matched_dns_name(message, expected):
    for name in message["question_names"] + message["answer_names"]:
        if name_matches(name, expected):
            return name
    return None


def _matched_nbt_name(message, expected):
    for name in message["names"]:
        if name_matches(name, expected):
            return name
    return None


def _dns_addresses(message, matched):
    ips = []
    ttl = None
    for record in message["answers"]:
        if not record["ip"] or not name_matches(record["name"], [matched]):
            continue
        if record["ip"] not in ips:
            ips.append(record["ip"])
        ttl = record["ttl"] if ttl is None else min(ttl, record["ttl"])
        if len(ips) == MAX_ANSWERED_IPS:
            break
    return ips, ttl


def _alert(kind, query_name, matched, ips, ttl, transaction_id, rcode, suffix=None):
    label = PROTOCOL_LABELS[kind]
    shown = ", ".join(ips)
    text = "%s %s -> %s" % (label, matched, shown)
    if ttl is not None:
        text = "%s ttl=%s" % (text, ttl)
    fields = {
        "PROTOCOL": label,
        "query_hostname": query_name,
        "QUERY_NAME": query_name,
        "MATCHED_NAME": matched,
        "ANSWERED_IPS": ips,
        "TTL": ttl,
        "TRANSACTION_ID": transaction_id,
        "RCODE": rcode,
        "response": text,
    }
    if suffix is not None:
        fields["SUFFIX"] = "0x%02X" % suffix
    return fields


def _parse_dns(data):
    header = _header(data)
    offset = 12
    questions = []
    for _ in range(header["qdcount"]):
        name, offset = _decode_dns_name(data, offset)
        offset = _skip(data, offset, 4)
        questions.append(name)

    answers = []
    for _ in range(header["ancount"] + header["nscount"] + header["arcount"]):
        record, offset = _read_rr(data, offset)
        answers.append(record)

    return {
        "transaction_id": header["transaction_id"],
        "response": header["response"],
        "rcode": header["rcode"],
        "question_names": questions,
        "answer_names": [record["name"] for record in answers],
        "answers": answers,
    }


def _parse_nbtns(data):
    header = _header(data)
    offset = 12
    names = []
    question_suffix = None
    for _ in range(header["qdcount"]):
        name, suffix, offset = _decode_nbt_name(data, offset)
        offset = _skip(data, offset, 4)
        names.append(name)
        question_suffix = suffix

    ips = []
    ttl = None
    answer_suffix = None
    for _ in range(header["ancount"] + header["nscount"] + header["arcount"]):
        name, suffix, offset = _decode_nbt_name(data, offset)
        names.append(name)
        rtype, _, record_ttl, rdata, offset = _read_rdata(data, offset)
        if rtype == NBT_TYPE_NB:
            ips.extend(_nbt_ips(rdata))
            ttl = record_ttl if ttl is None else min(ttl, record_ttl)
            answer_suffix = suffix

    return {
        "transaction_id": header["transaction_id"],
        "response": header["response"],
        "rcode": header["rcode"],
        "names": names,
        "ips": _cap_ips(ips),
        "ttl": ttl,
        "suffix": answer_suffix if answer_suffix is not None else question_suffix,
    }


def _header(data):
    if len(data) < 12:
        raise ProtocolError("packet is shorter than a header")
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", data, 0
    )
    if qdcount + ancount + nscount + arcount > MAX_RECORDS:
        raise ProtocolError("unreasonable record count")
    return {
        "transaction_id": transaction_id,
        "response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


def _decode_dns_name(data, offset):
    labels = []
    end_offset = None
    seen = set()
    hops = 0
    while True:
        if offset >= len(data) or hops > 128:
            raise ProtocolError("invalid DNS name")
        hops += 1
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer, end = _dns_pointer(data, offset, seen)
            end_offset = end_offset if end_offset is not None else end
            offset = pointer
            continue
        if length & 0xC0:
            raise ProtocolError("unsupported DNS label")
        if length == 0:
            end_offset = offset + 1 if end_offset is None else end_offset
            break
        label, offset = _dns_label(data, offset)
        labels.append(label)
    return ".".join(labels), end_offset


def _dns_pointer(data, offset, seen):
    if offset + 1 >= len(data):
        raise ProtocolError("truncated compression pointer")
    pointer = ((data[offset] & 0x3F) << 8) | data[offset + 1]
    if pointer in seen or pointer >= len(data):
        raise ProtocolError("bad compression pointer")
    seen.add(pointer)
    return pointer, offset + 2


def _dns_label(data, offset):
    length = data[offset]
    start = offset + 1
    if start + length > len(data):
        raise ProtocolError("label runs past end of packet")
    label = data[start : start + length].decode("ascii", errors="replace")
    return label, start + length


def _decode_nbt_name(data, offset):
    label, offset = _decode_dns_name(data, offset)
    if len(label) != 32:
        raise ProtocolError("not a NetBIOS name")
    raw = bytearray()
    for index in range(0, 32, 2):
        high = ord(label[index].upper()) - 0x41
        low = ord(label[index + 1].upper()) - 0x41
        if not (0 <= high <= 15 and 0 <= low <= 15):
            raise ProtocolError("invalid NetBIOS encoding")
        raw.append((high << 4) | low)
    base = raw[:15].decode("ascii", errors="replace").rstrip(" ")
    return base, raw[15], offset


def _read_rr(data, offset):
    name, offset = _decode_dns_name(data, offset)
    rtype, _, ttl, rdata, offset = _read_rdata(data, offset)
    return {"name": name, "ttl": ttl, "ip": _rr_ip(rtype, rdata)}, offset


def _read_rdata(data, offset):
    if offset + 10 > len(data):
        raise ProtocolError("truncated resource record")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise ProtocolError("resource data runs past end of packet")
    rdata = data[offset : offset + rdlength]
    return rtype, rclass, ttl, rdata, offset + rdlength


def _rr_ip(rtype, rdata):
    try:
        if rtype == DNS_TYPE_A and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
        if rtype == DNS_TYPE_AAAA and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
    except OSError:
        return None
    return None


def _nbt_ips(rdata):
    ips = []
    if len(rdata) >= 6 and len(rdata) % 6 == 0:
        chunks = range(0, len(rdata), 6)
        for offset in chunks:
            ips.append(socket.inet_ntoa(rdata[offset + 2 : offset + 6]))
        return _cap_ips(ips)
    if len(rdata) >= 4:
        return [socket.inet_ntoa(rdata[-4:])]
    return []


def _cap_ips(ips):
    result = []
    for ip in ips:
        if ip not in result:
            result.append(ip)
        if len(result) == MAX_ANSWERED_IPS:
            break
    return result


def _skip(data, offset, size):
    if offset + size > len(data):
        raise ProtocolError("truncated packet")
    return offset + size
