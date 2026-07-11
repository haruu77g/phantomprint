"""
phantomprint/correlator/signal_merger.py

Motor de correlación multi-señal con scoring bayesiano.
Combina señales heterogéneas (TCP/IP, TLS, DHCP, DNS, HTTP/2)
para construir un perfil de host con alta confianza.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from phantomprint.signatures.db import SignatureDB


@dataclass
class FingerprintSignal:
    """Señal individual generada por un parser de protocolo."""
    source: str          # "tcp_ip" | "tls" | "dhcp" | "dns" | "http2"
    raw_hash: str        # Hash/fingerprint del protocolo — se compara contra DB
    metadata: dict       # Campos crudos para debugging y output
    confidence: float    # Confianza intrínseca de esta señal (0.0 - 1.0)


@dataclass
class Candidate:
    """Candidato de OS/browser/device desde la DB de firmas."""
    id: str
    name: str
    type: str            # "os" | "browser" | "device"
    description: str
    matched_signals: list[str] = field(default_factory=list)


@dataclass
class HostProfile:
    """
    Perfil correlacionado de un host observado pasivamente.
    Se actualiza cada vez que llega una señal nueva del host.
    """
    ip: str
    signals: list[FingerprintSignal] = field(default_factory=list)

    os_candidates: list[Candidate] = field(default_factory=list)
    browser_candidates: list[Candidate] = field(default_factory=list)
    device_candidates: list[Candidate] = field(default_factory=list)

    composite_score: float = 0.0
    composite_hash: Optional[str] = None

    def best_os(self) -> Optional[Candidate]:
        return self.os_candidates[0] if self.os_candidates else None

    def best_browser(self) -> Optional[Candidate]:
        return self.browser_candidates[0] if self.browser_candidates else None

    def signal_sources(self) -> list[str]:
        return [s.source for s in self.signals]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "composite_score": self.composite_score,
            "composite_hash": self.composite_hash,
            "signals_observed": self.signal_sources(),
            "os": self.best_os().name if self.best_os() else "unknown",
            "browser": self.best_browser().name if self.best_browser() else "unknown",
            "os_candidates": [
                {"name": c.name, "matched_signals": c.matched_signals}
                for c in self.os_candidates
            ],
            "browser_candidates": [
                {"name": c.name, "matched_signals": c.matched_signals}
                for c in self.browser_candidates
            ],
            "signals": [
                {"source": s.source, "hash": s.raw_hash, "confidence": s.confidence, **s.metadata}
                for s in self.signals
            ],
        }


class SignalMerger:
    """
    Correlaciona múltiples señales pasivas en un perfil de host.

    Principio clave: ninguna señal sola es definitiva.
    La intersección de N señales independientes multiplica la certeza.

    Scoring bayesiano:
      composite_score = 1 - Π(1 - w_i * c_i)
      Donde:
        w_i = peso del protocolo (especificidad histórica observada)
        c_i = confianza de la señal individual
    """

    # Peso por protocolo — basado en especificidad y unicidad observada
    SIGNAL_WEIGHTS = {
        "tcp_ip": 0.25,   # OS stack — bueno pero puede compartirse entre OS
        "tls":    0.30,   # JA4 — muy específico por client library
        "dhcp":   0.25,   # Option 55 — muy específico por OS
        "http2":  0.12,   # Header order — específico por browser/app
        "dns":    0.08,   # Comportamiento DNS — menos específico
    }

    def __init__(self, signature_db: "SignatureDB"):
        self.db = signature_db
        self._profiles: dict[str, HostProfile] = {}

    def ingest_signal(self, ip: str, signal: FingerprintSignal) -> HostProfile:
        """
        Ingiere una señal para un host y recalcula el perfil completo.
        
        Si ya existe una señal del mismo tipo para ese host,
        la reemplazamos por la más reciente (asumimos que es más precisa).
        """
        if ip not in self._profiles:
            self._profiles[ip] = HostProfile(ip=ip)

        profile = self._profiles[ip]

        # Reemplazar señal del mismo tipo si existe
        profile.signals = [s for s in profile.signals if s.source != signal.source]
        profile.signals.append(signal)

        # Recalcular perfil
        self._match_signatures(profile)
        self._compute_composite_score(profile)
        self._compute_composite_hash(profile)

        return profile

    def _match_signatures(self, profile: HostProfile) -> None:
        """
        Busca en la DB de firmas para cada señal disponible.
        
        Estrategia de matching:
        1. Buscar candidatos para cada señal individualmente
        2. Calcular intersección (candidatos que matchean múltiples señales)
        3. Si hay intersección → usarla (alta confianza)
        4. Si no → usar unión con penalización de score (fallback)
        """
        candidate_sets_os: list[set[str]] = []
        candidate_sets_browser: list[set[str]] = []
        candidate_sets_device: list[set[str]] = []

        all_candidates: dict[str, Candidate] = {}

        for signal in profile.signals:
            matches = self.db.query_by_signal(
                source=signal.source,
                raw_hash=signal.raw_hash,
            )

            os_ids = set()
            browser_ids = set()
            device_ids = set()

            for m in matches:
                cid = m["id"]
                candidate = Candidate(
                    id=cid,
                    name=m["name"],
                    type=m["type"],
                    description=m.get("description", ""),
                    matched_signals=[signal.source],
                )

                if cid in all_candidates:
                    # Acumular señales que matchearon este candidato
                    all_candidates[cid].matched_signals.append(signal.source)
                else:
                    all_candidates[cid] = candidate

                if m["type"] == "os":
                    os_ids.add(cid)
                elif m["type"] == "browser":
                    browser_ids.add(cid)
                elif m["type"] == "device":
                    device_ids.add(cid)

            if os_ids:
                candidate_sets_os.append(os_ids)
            if browser_ids:
                candidate_sets_browser.append(browser_ids)
            if device_ids:
                candidate_sets_device.append(device_ids)

        # Resolver candidatos finales por categoría
        profile.os_candidates = self._resolve_candidates(
            candidate_sets_os, all_candidates, "os"
        )
        profile.browser_candidates = self._resolve_candidates(
            candidate_sets_browser, all_candidates, "browser"
        )
        profile.device_candidates = self._resolve_candidates(
            candidate_sets_device, all_candidates, "device"
        )

    def _resolve_candidates(
        self,
        candidate_sets: list[set[str]],
        all_candidates: dict[str, Candidate],
        category: str,
    ) -> list[Candidate]:
        """
        Resuelve los candidatos finales para una categoría.
        Prioriza intersección sobre unión.
        Ordena por número de señales que matchearon (más = más confianza).
        """
        if not candidate_sets:
            return []

        if len(candidate_sets) > 1:
            intersection = set.intersection(*candidate_sets)
            final_ids = intersection if intersection else set.union(*candidate_sets)
        else:
            final_ids = candidate_sets[0]

        candidates = [
            all_candidates[cid]
            for cid in final_ids
            if cid in all_candidates and all_candidates[cid].type == category
        ]

        # Ordenar por número de señales que lo matchearon (descendente)
        candidates.sort(key=lambda c: len(c.matched_signals), reverse=True)
        return candidates

    def _compute_composite_score(self, profile: HostProfile) -> None:
        """
        Score bayesiano: cada señal independiente confirmada
        incrementa la probabilidad de identificación correcta.
        
        Formula: score = 1 - Π(1 - w_i * c_i) para cada señal i
        
        Ejemplos:
          Solo TCP/IP (c=0.6):          score = 1 - (1 - 0.25*0.6) = 0.15
          TCP/IP + TLS (c=0.8):         score = 1 - (0.85)(0.76)   = 0.354
          TCP/IP + TLS + DHCP (c=0.9):  score = 1 - (0.85)(0.76)(0.775) = 0.499
        """
        if not profile.signals:
            profile.composite_score = 0.0
            return

        complement_product = 1.0
        for signal in profile.signals:
            weight = self.SIGNAL_WEIGHTS.get(signal.source, 0.05)
            contribution = weight * signal.confidence
            complement_product *= (1.0 - contribution)

        profile.composite_score = round(1.0 - complement_product, 4)

    def _compute_composite_hash(self, profile: HostProfile) -> None:
        """
        Hash determinístico del perfil completo.
        
        Útil para:
        - Detectar cambios de comportamiento de un host en el tiempo
        - Correlacionar el mismo host a través de múltiples sensores
        - Trackear actores que rotan infraestructura
        
        Blake2b: más rápido que SHA256 para este uso interno.
        """
        signal_hashes = sorted(
            f"{s.source}:{s.raw_hash}" for s in profile.signals
        )
        raw = "|".join(signal_hashes).encode()
        profile.composite_hash = hashlib.blake2b(raw, digest_size=16).hexdigest()

    def get_profile(self, ip: str) -> Optional[HostProfile]:
        return self._profiles.get(ip)

    def get_all_profiles(self) -> list[HostProfile]:
        return list(self._profiles.values())

    def profile_count(self) -> int:
        return len(self._profiles)
