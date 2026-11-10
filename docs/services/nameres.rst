Name-resolution canary
======================

OpenCanary can pretend to be a Windows client looking up a hostname that
should not exist. If another host answers, that host is claiming the name
and is logged. The canary sends queries only. It does not answer lookups
from other machines.

Three protocols share one implementation:

* **LLMNR** (``llmnr.enabled``) multicasts to ``224.0.0.252:5355``.
* **NBT-NS** (``nbtns.enabled``) broadcasts a NetBIOS name query. The
  default port is 137, so the process must be allowed to bind that port.
* **mDNS** (``mdns.enabled``) multicasts to ``224.0.0.251:5353``. A short
  hostname such as ``DC03`` is queried as ``DC03.local``.

Enabling ``llmnr`` does not enable the other two. Turn on each protocol you
want. NBT-NS and mDNS use ``llmnr.hostname`` (or ``llmnr.hostnames``) when
they do not have their own name configured.

.. code-block:: json

    {
        "llmnr.enabled": true,
        "llmnr.hostname": "DC03",
        "llmnr.hostnames": ["DC03", "FS01"],
        "llmnr.query_interval": 60,
        "llmnr.query_splay": 5,
        "llmnr.allowlist": [],
        "nbtns.enabled": true,
        "nbtns.port": 137,
        "nbtns.suffix": 32,
        "nbtns.broadcast": "255.255.255.255",
        "nbtns.allowlist": [],
        "mdns.enabled": true,
        "mdns.port": 5353,
        "mdns.allowlist": [],
        "nameres.allowlist": ["10.0.0.10", "10.0.0.0/24"],
        "nameres.response_window": 5
    }

``llmnr.hostnames`` replaces ``llmnr.hostname`` when it is set. A single
string is still accepted. ``nameres.allowlist`` applies to every protocol,
and each protocol may add its own ``allowlist``. Entries are IP addresses
or CIDR ranges. An allowlisted source is not alerted on, which is how you
silence a resolver that is supposed to answer.

Choose a name that no host on the segment owns. If the canary host itself
answers for the name, or a real resolver is expected to, add that source to
the allowlist.

An alert includes the protocol, the name that was queried, the name that
matched, the answered IP addresses, the TTL, and the transaction id. LLMNR
keeps log type ``19001``. NBT-NS is ``19002`` and mDNS is ``19003``. The
probes are IPv4 only.

LLMNR and NBT-NS only alert on a reply to a query this process sent, and
only while ``nameres.response_window`` seconds have not elapsed. mDNS
replies often use transaction id 0, so those alerts match the configured
name instead of an id. A reply with no address is ignored.

Multicast and broadcast do not cross most Docker bridges. Run with host
networking if the canary must reach the local segment. On a multi-homed
host, set ``device.listen_addr`` so the multicast group is joined and queried
on the intended interface. On macOS, UDP 5353 may already be taken by the
system mDNS listener, and a host running Samba or Avahi may already own port
137 or 5353.
