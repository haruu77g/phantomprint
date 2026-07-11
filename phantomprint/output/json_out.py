"""
phantomprint/output/json_out.py

Renderer de output JSON — guarda perfiles a disco.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phantomprint.correlator.signal_merger import HostProfile


class JSONRenderer:
    """Serializa perfiles de host a JSON."""

    def save(self, profiles: list["HostProfile"], path: Path) -> None:
        output = {
            "phantomprint_version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "host_count": len(profiles),
            "hosts": [p.to_dict() for p in profiles],
        }

        with open(path, "w") as f:
            json.dump(output, f, indent=2, default=str)
