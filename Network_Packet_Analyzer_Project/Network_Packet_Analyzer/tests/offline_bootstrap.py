"""Optional test-only adapter for hosts that prohibit interface discovery.

Set NPA_TEST_OFFLINE=1 before tests on a restricted CI host. This suppresses
Scapy's network-interface/routing discovery; packet parsing and file I/O remain
real. It does not grant capture permissions or simulate a live capture.
"""
import os

if os.environ.get("NPA_TEST_OFFLINE") == "1":
    from scapy.config import conf
    import scapy.interfaces  # initializes conf.ifaces without probing sockets
    conf.route_autoload = False
    conf.route6_autoload = False
    conf.ifaces.reload = lambda: None
