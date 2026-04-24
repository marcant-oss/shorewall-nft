"""NftBackend — adapter around shorewall_nft.nft.emitter.emit_nft."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from shorewall_nft.compiler.backends import register_backend

if TYPE_CHECKING:
    from shorewall_nft.compiler.ir import FirewallIR


@dataclass
class NftBackend:
    name: str = field(default="nft")

    def emit(self, ir: "FirewallIR") -> str:
        from shorewall_nft.nft.emitter import emit_nft

        return emit_nft(ir)


register_backend(NftBackend())
