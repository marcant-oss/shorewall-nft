"""keepalived integration — SNMP (Unix socket) + traps + D-Bus methods.

See ``docs/shorewalld/keepalived-snmp.md`` for the operator reference.

Module layout:

* :mod:`shorewalld.keepalived.mib` — generated OID tables
  (``tools/gen_keepalived_mib.py`` regenerates from the pinned
  upstream MIB in ``third_party/keepalived-mib/``).
* :mod:`shorewalld.keepalived.snmp_client` — ``python-netsnmp``
  wrapper over ``unix:/run/snmpd/snmpd.sock``; MIB-driven walker
  returning a :class:`KeepalivedSnapshot`.
* :mod:`shorewalld.keepalived.trap_listener` — ``pysnmp``
  ``NotificationReceiver`` on a separate Unix DGRAM socket
  (snmpd ``trap2sink unix:…`` forwards into it).
* :mod:`shorewalld.keepalived.dbus_client` — state-changing keepalived
  D-Bus methods (PrintData, PrintStats, ReloadConfig, SendGarp)
  surfaced as shorewalld control-socket commands.
* :mod:`shorewalld.keepalived.dispatcher` — parent-side event
  dispatcher, pattern-borrowed from :class:`shorewalld.log_dispatcher.LogDispatcher`.
* :mod:`shorewalld.keepalived.metrics` — auto-registered Prometheus
  families derived from the MIB at daemon startup.

Public re-exports (for ``from shorewalld.keepalived import X``):
"""

from shorewalld.keepalived.dispatcher import KeepalivedDispatcher
from shorewalld.keepalived.metrics import KeepalivedCollector
from shorewalld.keepalived.snmp_client import KeepalivedSnapshot

__all__ = [
    "KeepalivedCollector",
    "KeepalivedDispatcher",
    "KeepalivedSnapshot",
]
