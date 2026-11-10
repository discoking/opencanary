import importlib.util
import socket
import struct
import unittest
from pathlib import Path


def _load_namereslib():
    """Load the stdlib helper without importing opencanary.modules.

    That package init imports Twisted, which these packet tests do not need.
    """
    path = Path(__file__).resolve().parents[1] / "modules" / "namereslib.py"
    spec = importlib.util.spec_from_file_location("namereslib", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lib = _load_namereslib()
build_llmnr_query = lib.build_llmnr_query
build_nbtns_query = lib.build_nbtns_query
collect_allowlist = lib.collect_allowlist
collect_names = lib.collect_names
consider_response = lib.consider_response
encode_dns_name = lib.encode_dns_name
encode_nbt_name = lib.encode_nbt_name
parse_allowlist = lib.parse_allowlist
source_allowed = lib.source_allowed


class FakeConfig(object):
    def __init__(self, values):
        self.values = values

    def getVal(self, key, default=None):
        if key in self.values:
            return self.values[key]
        if default is not None:
            return default
        raise KeyError(key)


def dns_response(txid, name, ip, ttl=30, flags=0x8000):
    question = encode_dns_name(name) + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return header + question + answer


def nbt_response(txid, name, ip, ttl=30):
    question = encode_nbt_name(name) + struct.pack("!HH", 0x20, 1)
    header = struct.pack("!HHHHHH", txid, 0x8500, 1, 1, 0, 0)
    rdata = b"\x00\x00" + socket.inet_aton(ip)
    answer = encode_nbt_name(name) + struct.pack("!HHIH", 0x20, 1, ttl, len(rdata))
    return header + question + answer + rdata


def dns_response_with_additional(txid, name, ip, ttl=60):
    question = encode_dns_name(name) + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, 0, 0, 1)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return header + question + record


class NameResTests(unittest.TestCase):
    def test_llmnr_response_records_address_and_ttl(self):
        outstanding = {0x1234: ("DC03", 100)}
        packet = dns_response(0x1234, "dc03", "10.1.2.3", ttl=30)

        finding = consider_response(packet, "llmnr", ["DC03"], outstanding, 90)

        self.assertEqual(finding["PROTOCOL"], "LLMNR")
        self.assertEqual(finding["QUERY_NAME"], "DC03")
        self.assertEqual(finding["MATCHED_NAME"], "dc03")
        self.assertEqual(finding["ANSWERED_IPS"], ["10.1.2.3"])
        self.assertEqual(finding["TTL"], 30)
        self.assertEqual(finding["TRANSACTION_ID"], 0x1234)
        self.assertIn("10.1.2.3", finding["response"])

    def test_llmnr_ignores_unknown_transaction_and_queries(self):
        outstanding = {0x1234: ("DC03", 100)}
        wrong_id = dns_response(0x99, "DC03", "10.1.2.3")
        query = build_llmnr_query(0x1234, "DC03")

        self.assertIsNone(
            consider_response(wrong_id, "llmnr", ["DC03"], outstanding, 90)
        )
        self.assertIsNone(consider_response(query, "llmnr", ["DC03"], outstanding, 90))
        self.assertIsNone(
            consider_response(
                dns_response(0x1234, "DC03", "10.1.2.3"),
                "llmnr",
                ["DC03"],
                outstanding,
                101,
            )
        )

    def test_mdns_matches_local_name_without_transaction_id(self):
        packet = dns_response(0, "FS01.local", "10.9.9.9", ttl=120)

        finding = consider_response(packet, "mdns", ["FS01", "FS01.local"], {}, 0)

        self.assertEqual(finding["PROTOCOL"], "mDNS")
        self.assertEqual(finding["ANSWERED_IPS"], ["10.9.9.9"])
        self.assertEqual(finding["TTL"], 120)
        self.assertIsNone(consider_response(packet, "mdns", ["DC03"], {}, 0))

    def test_mdns_reads_addresses_from_additional_section(self):
        packet = dns_response_with_additional(0, "FS01.local", "10.9.9.10", ttl=45)

        finding = consider_response(packet, "mdns", ["FS01.local"], {}, 0)

        self.assertEqual(finding["ANSWERED_IPS"], ["10.9.9.10"])
        self.assertEqual(finding["TTL"], 45)

    def test_query_wire_format(self):
        llmnr = build_llmnr_query(0x1234, "DC03")
        nbtns = build_nbtns_query(7, "FS01")

        self.assertEqual(struct.unpack("!H", llmnr[:2])[0], 0x1234)
        self.assertEqual(llmnr[12:], b"\x04DC03\x00" + struct.pack("!HH", 1, 1))
        self.assertEqual(nbtns[12], 0x20)
        self.assertEqual(nbtns[12 + 33], 0)
        self.assertEqual(struct.unpack("!H", nbtns[2:4])[0] & 0x8000, 0)

    def test_nbtns_response_records_suffix_and_address(self):
        outstanding = {7: ("FS01", 50)}
        packet = nbt_response(7, "fs01", "192.168.1.50", ttl=300)

        finding = consider_response(packet, "nbtns", ["FS01"], outstanding, 10)

        self.assertEqual(finding["PROTOCOL"], "NBT-NS")
        self.assertEqual(finding["QUERY_NAME"], "FS01")
        self.assertEqual(finding["ANSWERED_IPS"], ["192.168.1.50"])
        self.assertEqual(finding["TTL"], 300)
        self.assertEqual(finding["SUFFIX"], "0x20")
        self.assertIsNone(
            consider_response(
                build_nbtns_query(7, "FS01"), "nbtns", ["FS01"], outstanding, 10
            )
        )

    def test_malformed_packet_is_ignored(self):
        self.assertIsNone(consider_response(b"\x00\x01", "llmnr", ["DC03"], {}, 0))
        self.assertIsNone(consider_response(b"", "mdns", ["DC03"], {}, 0))

    def test_compression_pointer_loop_is_ignored(self):
        header = struct.pack("!HHHHHH", 0, 0x8000, 0, 1, 0, 0)
        record = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 30, 4)
            + socket.inet_aton("10.0.0.1")
        )

        self.assertIsNone(consider_response(header + record, "mdns", ["DC03"], {}, 0))

    def test_allowlist_matches_ip_and_cidr(self):
        networks = parse_allowlist(["10.0.0.10", "192.168.5.0/24"])

        self.assertTrue(source_allowed("10.0.0.10", networks))
        self.assertTrue(source_allowed("192.168.5.20", networks))
        self.assertFalse(source_allowed("10.0.0.11", networks))
        self.assertFalse(source_allowed("not-an-ip", networks))
        with self.assertRaises(ValueError):
            parse_allowlist(["nope"])

    def test_query_splay_accepts_zero_but_interval_does_not(self):
        config = FakeConfig({"llmnr.query_splay": 0})

        self.assertEqual(
            lib.collect_number(config, ("llmnr.query_splay",), 5, allow_zero=True),
            0.0,
        )
        with self.assertRaises(ValueError):
            lib.collect_number(config, ("llmnr.query_splay",), 5)
        with self.assertRaises(ValueError):
            lib.collect_number(FakeConfig({"x": -1}), ("x",), 5)

    def test_names_fall_back_to_llmnr_hostname(self):
        config = FakeConfig({"llmnr.hostname": "DC03", "mdns.hostnames": ["PRN1"]})

        self.assertEqual(collect_names(config, "nbtns"), ["DC03"])
        self.assertEqual(collect_names(config, "mdns"), ["PRN1"])
        self.assertEqual(
            collect_allowlist(
                FakeConfig(
                    {"nameres.allowlist": ["10.0.0.1"], "llmnr.allowlist": ["10.0.0.2"]}
                ),
                "llmnr",
            )[1].network_address.exploded,
            "10.0.0.2",
        )


if __name__ == "__main__":
    unittest.main()
