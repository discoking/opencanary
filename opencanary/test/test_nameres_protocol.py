import socket
import struct
import time
import unittest

from opencanary.modules.nameres import (
    CanaryLLMNR,
    CanaryMDNS,
    CanaryNBTNS,
    NameResProtocol,
)


class FakeConfig(object):
    def __init__(self, values=None):
        self.values = values or {}

    def getVal(self, key, default=None):
        if key in self.values:
            return self.values[key]
        if default is not None:
            return default
        raise KeyError(key)


class FakeLogger(object):
    LOG_LLMNR_QUERY_RESPONSE = 19001
    LOG_NBTNS_QUERY_RESPONSE = 19002
    LOG_MDNS_QUERY_RESPONSE = 19003

    def __init__(self):
        self.events = []

    def log(self, data):
        self.events.append(data)


class FakeTransport(object):
    def getHost(self):
        return type("Host", (), {"host": "0.0.0.0", "port": 5355})()

    def getPeer(self):
        return type("Peer", (), {"host": "0.0.0.0", "port": 0})()


def dns_response(txid, name, ip, ttl=30):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", txid, 0x8000, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return header + question + answer


class NameResProtocolTests(unittest.TestCase):
    def test_llmnr_reply_is_logged_with_source(self):
        logger = FakeLogger()
        service = CanaryLLMNR(FakeConfig({"llmnr.hostname": "DC03"}), logger)
        protocol = NameResProtocol()
        protocol.factory = service
        protocol.transport = FakeTransport()
        protocol.outstanding = {0x4444: ("DC03", time.monotonic() + 5)}

        protocol.datagramReceived(
            dns_response(0x4444, "dc03", "10.1.2.3"), ("10.1.2.3", 5355)
        )

        self.assertEqual(len(logger.events), 1)
        event = logger.events[0]
        self.assertEqual(event["logtype"], 19001)
        self.assertEqual(event["src_host"], "10.1.2.3")
        self.assertEqual(event["src_port"], 5355)
        self.assertEqual(event["logdata"]["ANSWERED_IPS"], ["10.1.2.3"])
        self.assertEqual(event["logdata"]["PROTOCOL"], "LLMNR")

    def test_allowlisted_reply_is_not_logged(self):
        logger = FakeLogger()
        service = CanaryLLMNR(
            FakeConfig({"llmnr.hostname": "DC03", "llmnr.allowlist": ["10.0.0.0/24"]}),
            logger,
        )
        protocol = NameResProtocol()
        protocol.factory = service
        protocol.transport = FakeTransport()
        protocol.outstanding = {0x4444: ("DC03", time.monotonic() + 5)}

        protocol.datagramReceived(
            dns_response(0x4444, "DC03", "10.0.0.9"), ("10.0.0.9", 5355)
        )

        self.assertEqual(logger.events, [])

    def test_mdns_reply_matches_configured_local_name(self):
        logger = FakeLogger()
        service = CanaryMDNS(FakeConfig({"mdns.hostname": "PRN1"}), logger)
        protocol = NameResProtocol()
        protocol.factory = service
        protocol.transport = FakeTransport()
        protocol.outstanding = {}

        protocol.datagramReceived(
            dns_response(0, "PRN1.local", "10.2.3.4"), ("10.2.3.4", 5353)
        )

        self.assertEqual(len(logger.events), 1)
        self.assertEqual(logger.events[0]["logtype"], 19003)
        self.assertEqual(logger.events[0]["logdata"]["PROTOCOL"], "mDNS")

    def test_services_use_expected_names_and_destinations(self):
        llmnr = CanaryLLMNR(FakeConfig(), FakeLogger())
        nbtns = CanaryNBTNS(
            FakeConfig({"nbtns.hostname": "FS01", "nbtns.suffix": 32}), FakeLogger()
        )
        mdns = CanaryMDNS(FakeConfig({"mdns.hostname": "FS01"}), FakeLogger())

        self.assertEqual(llmnr.query_names, ["DC03"])
        self.assertEqual(llmnr.destinations, [("224.0.0.252", 5355)])
        self.assertEqual(nbtns.destinations, [("255.255.255.255", 137)])
        self.assertEqual(nbtns.suffix, 32)
        self.assertEqual(mdns.destinations, [("224.0.0.251", 5353)])
        self.assertEqual(mdns.match_names, ["FS01", "FS01.local"])
        self.assertEqual(mdns.logtype, 19003)


if __name__ == "__main__":
    unittest.main()
