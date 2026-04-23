"""Shared constants for the verify package.

The 3-namespace simulation topology used by ``simulate.py`` (and a
few peer validators that operate inside its namespaces) is defined
here so that no caller has to reach into ``simulate.py`` for a
plain string constant.
"""

from __future__ import annotations

# 3-namespace test topology — names match what simulate.py creates.
NS_SRC = "shorewall-next-sim-src"
NS_FW = "shorewall-next-sim-fw"
NS_DST = "shorewall-next-sim-dst"

# Default source IP used by connstate probes when the caller does
# not override it.
DEFAULT_SRC = "192.0.2.69"
