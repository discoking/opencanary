"""Client-side name-resolution canary.

Sends lookups for configured hostnames over LLMNR, NBT-NS, and mDNS, then
logs any host that answers. Expected resolvers can be allowlisted so a real
domain controller does not page on every probe.
"""

import random
import socket
import time

from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.address import IPv4Address
from twisted.internet.protocol import DatagramProtocol

from opencanary.modules import CanaryService
from opencanary.modules.namereslib import (
    build_llmnr_query,
    build_mdns_query,
    build_nbtns_query,
    collect_allowlist,
    collect_names,
    collect_number,
    consider_response,
    expand_match_names,
    mdns_query_name,
    nbt_name_ok,
    source_allowed,
)

LLMNR_GROUP = "224.0.0.252"
MDNS_GROUP = "224.0.0.251"
NBT_BROADCAST = "255.255.255.255"


class NameResProtocol(DatagramProtocol):
    def startProtocol(self):
        self.outstanding = {}
        self._loop = None
        self._notes = set()
        self._prepare_socket()
        self._schedule()

    def stopProtocol(self):
        if self._loop is not None and self._loop.active():
            self._loop.cancel()
        self._loop = None

    def _prepare_socket(self):
        sock = self.transport.getHandle()
        if self.factory.broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        group = self.factory.multicast_group
        if not group:
            return
        try:
            iface = self.factory.listen_addr or "0.0.0.0"
            if iface != "0.0.0.0":
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(iface),
                )
            membership = socket.inet_aton(group) + socket.inet_aton(iface)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        except OSError as exc:
            self._note("join %s failed: %s" % (group, exc))

    def _schedule(self):
        self._send_queries()
        delay = self.factory.query_interval + random.uniform(
            -self.factory.query_splay, self.factory.query_splay
        )
        if delay < 1:
            delay = 1
        self._loop = self.factory.reactor.callLater(delay, self._schedule)

    def _send_queries(self):
        self._prune(time.monotonic())
        for name in self.factory.query_names:
            txid = self._new_txid()
            packet, query_name, stored_id = self.factory.build_probe(name, txid)
            if packet is None:
                self._note(
                    "skipping %r; it is not a valid name for this protocol" % name
                )
                continue
            if stored_id:
                expiry = time.monotonic() + self.factory.response_window
                self.outstanding[stored_id] = (query_name, expiry)
            self._write(packet)

    def _new_txid(self):
        for _ in range(8):
            txid = random.randint(1, 0xFFFF)
            if txid not in self.outstanding:
                return txid
        return random.randint(1, 0xFFFF)

    def _write(self, packet):
        for dest in self.factory.destinations:
            try:
                self.transport.write(packet, dest)
            except Exception as exc:  # noqa: BLE001
                self._note("send to %s:%s failed: %s" % (dest[0], dest[1], exc))

    def _prune(self, now):
        expired = [txid for txid, entry in self.outstanding.items() if now > entry[1]]
        for txid in expired:
            del self.outstanding[txid]

    def _note(self, message):
        if message in self._notes:
            return
        self._notes.add(message)
        print("Name-resolution canary (%s): %s" % (self.factory.NAME, message))

    def datagramReceived(self, data, host_and_port):
        finding = consider_response(
            data,
            self.factory.KIND,
            self.factory.match_names,
            self.outstanding,
            time.monotonic(),
        )
        if finding is None:
            return
        source_ip, source_port = host_and_port
        if source_allowed(source_ip, self.factory.allow_networks):
            return
        self._log(finding, source_ip, source_port)

    def _log(self, finding, source_ip, source_port):
        if ":" in source_ip:
            us = self.transport.getHost()
            self.factory.log(
                finding,
                src_host=source_ip,
                src_port=source_port,
                dst_host=us.host,
                dst_port=us.port,
            )
            return
        self.transport.getPeer = lambda: IPv4Address("UDP", source_ip, source_port)
        self.factory.log(finding, transport=self.transport)


class CanaryNameRes(CanaryService):
    NAME = "nameres"
    KIND = "llmnr"
    DEFAULT_PORT = 5355
    MULTICAST = None
    BROADCAST = False
    LOGTYPE_ATTR = "LOG_LLMNR_QUERY_RESPONSE"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("%s.port" % self.NAME, default=self.DEFAULT_PORT))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.query_names = collect_names(config, self.NAME)
        self.match_names = expand_match_names(self.KIND, self.query_names)
        self.query_interval = collect_number(
            config,
            (
                "%s.query_interval" % self.NAME,
                "nameres.query_interval",
                "llmnr.query_interval",
            ),
            60,
        )
        self.query_splay = collect_number(
            config,
            (
                "%s.query_splay" % self.NAME,
                "nameres.query_splay",
                "llmnr.query_splay",
            ),
            5,
            allow_zero=True,
        )
        self.response_window = collect_number(
            config,
            ("nameres.response_window", "%s.response_window" % self.NAME),
            5,
        )
        self.allow_networks = collect_allowlist(config, self.NAME)
        self.suffix = self._suffix(config)
        self.destinations = self._destinations(config)
        self.multicast_group = self.MULTICAST
        self.broadcast = self.BROADCAST
        self.reactor = reactor
        self.logtype = getattr(self.logger, self.LOGTYPE_ATTR)

    def _suffix(self, config):
        if self.KIND != "nbtns":
            return 0x20
        suffix = int(config.getVal("nbtns.suffix", default=32))
        if not 0 <= suffix <= 255:
            raise ValueError("nbtns.suffix must be between 0 and 255")
        return suffix

    def _destinations(self, config):
        if self.KIND == "nbtns":
            broadcast = config.getVal("nbtns.broadcast", default=NBT_BROADCAST)
            socket.inet_aton(broadcast)
            return [(broadcast, self.port)]
        if self.KIND == "mdns":
            return [(MDNS_GROUP, self.port)]
        return [(LLMNR_GROUP, self.port)]

    def build_probe(self, name, txid):
        if self.KIND == "nbtns":
            if not nbt_name_ok(name):
                return None, None, None
            packet = build_nbtns_query(txid, name, self.suffix)
            return packet, name.strip().upper(), txid
        if self.KIND == "mdns":
            query_name = mdns_query_name(name)
            return build_mdns_query(query_name), query_name, 0
        query_name = name.strip().rstrip(".")
        return build_llmnr_query(txid, query_name), query_name, txid

    def getService(self):
        protocol = NameResProtocol()
        protocol.factory = self
        return internet.UDPServer(self.port, protocol, interface=self.listen_addr)


class CanaryLLMNR(CanaryNameRes):
    NAME = "llmnr"
    KIND = "llmnr"
    DEFAULT_PORT = 5355
    MULTICAST = LLMNR_GROUP
    LOGTYPE_ATTR = "LOG_LLMNR_QUERY_RESPONSE"


class CanaryNBTNS(CanaryNameRes):
    NAME = "nbtns"
    KIND = "nbtns"
    DEFAULT_PORT = 137
    BROADCAST = True
    LOGTYPE_ATTR = "LOG_NBTNS_QUERY_RESPONSE"


class CanaryMDNS(CanaryNameRes):
    NAME = "mdns"
    KIND = "mdns"
    DEFAULT_PORT = 5353
    MULTICAST = MDNS_GROUP
    LOGTYPE_ATTR = "LOG_MDNS_QUERY_RESPONSE"
