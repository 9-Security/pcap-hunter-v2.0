"""IOC priority scoring for threat analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Default total number of VirusTotal engines for normalization
VT_DEFAULT_TOTAL_ENGINES = 70

# Default synthetic VT score for JA3 malware matches (71% detection rate)
JA3_MALWARE_DEFAULT_DETECTIONS = 50


@dataclass
class ScoredIOC:
    """An IOC with priority score and breakdown."""

    ioc_type: str
    value: str
    priority_score: float  # 0.0 - 1.0
    priority_label: str  # critical, high, medium, low
    factors: dict[str, dict[str, Any]]  # factor -> {value, contribution}
    recommendation: str

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.ioc_type,
            "value": self.value,
            "priority_score": round(self.priority_score, 3),
            "priority_label": self.priority_label,
            "factors": self.factors,
            "recommendation": self.recommendation,
        }


# Default scoring weights
DEFAULT_WEIGHTS = {
    # OSINT signals (50% total)
    "vt_detections": 0.25,  # VirusTotal detection ratio
    "greynoise_malicious": 0.15,  # GreyNoise classification
    "abuseipdb_score": 0.10,  # AbuseIPDB confidence
    # Behavioral signals (35% total)
    "beacon_score": 0.15,  # C2 beaconing likelihood
    "connection_count": 0.10,  # Frequency of communication
    "data_volume": 0.10,  # Amount of data transferred
    # Context signals (15% total)
    "ja3_malware_match": 0.08,  # Known malicious fingerprint
    "dga_match": 0.04,  # DGA domain
    "self_signed_cert": 0.03,  # Suspicious certificate
}

# Default priority thresholds (configurable per instance)
DEFAULT_PRIORITY_THRESHOLDS = {
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.0,
}

# Backwards compatibility alias
PRIORITY_THRESHOLDS = DEFAULT_PRIORITY_THRESHOLDS


class IOCScorer:
    """Score IOCs by threat priority."""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        thresholds: dict[str, float] | None = None,
    ):
        """
        Initialize scorer with optional custom weights and thresholds.

        Args:
            weights: Custom scoring weights (default: DEFAULT_WEIGHTS)
            thresholds: Custom priority thresholds (default: DEFAULT_PRIORITY_THRESHOLDS)
        """
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self.thresholds = thresholds or DEFAULT_PRIORITY_THRESHOLDS.copy()

    def score_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        osint_data: dict | None = None,
        behavioral_data: dict | None = None,
        context_data: dict | None = None,
    ) -> ScoredIOC:
        """
        Calculate priority score for an IOC.

        Args:
            ioc_value: The IOC value
            ioc_type: IOC type (ip, domain, hash, ja3)
            osint_data: OSINT enrichment data
            behavioral_data: Behavioral analysis data
            context_data: Additional context

        Returns:
            ScoredIOC with score and breakdown
        """
        osint_data = osint_data or {}
        behavioral_data = behavioral_data or {}
        context_data = context_data or {}

        factors = {}
        total_score = 0.0

        # OSINT scoring
        osint_score, osint_factors = self._score_osint(osint_data, ioc_type)
        factors.update(osint_factors)
        total_score += osint_score

        # Behavioral scoring
        behavioral_score, behavioral_factors = self._score_behavioral(behavioral_data)
        factors.update(behavioral_factors)
        total_score += behavioral_score

        # Context scoring
        context_score, context_factors = self._score_context(context_data)
        factors.update(context_factors)
        total_score += context_score

        # Normalize score to 0-1
        total_score = min(max(total_score, 0.0), 1.0)

        # Determine priority label
        priority_label = self._get_priority_label(total_score)

        # Generate recommendation
        recommendation = self._generate_recommendation(total_score, factors, ioc_type)

        return ScoredIOC(
            ioc_type=ioc_type,
            value=ioc_value,
            priority_score=total_score,
            priority_label=priority_label,
            factors=factors,
            recommendation=recommendation,
        )

    def _score_osint(self, osint_data: dict, ioc_type: str) -> tuple[float, dict]:
        """Score based on OSINT data."""
        score = 0.0
        factors = {}

        # VirusTotal
        vt_data = osint_data.get("virustotal", {})
        if vt_data:
            detections = vt_data.get("detections", 0)
            total = vt_data.get("total", VT_DEFAULT_TOTAL_ENGINES)
            if total > 0:
                vt_ratio = detections / total
                vt_contribution = vt_ratio * self.weights["vt_detections"]
                score += vt_contribution
                factors["vt_detections"] = {
                    "value": f"{detections}/{total}",
                    "contribution": round(vt_contribution, 3),
                }

        # GreyNoise
        gn_data = osint_data.get("greynoise", {})
        if gn_data:
            classification = gn_data.get("classification", "unknown")
            if classification == "malicious":
                gn_contribution = self.weights["greynoise_malicious"]
                score += gn_contribution
                factors["greynoise"] = {
                    "value": classification,
                    "contribution": round(gn_contribution, 3),
                }
            elif classification == "benign":
                # Reduce score for known benign
                factors["greynoise"] = {
                    "value": classification,
                    "contribution": 0.0,
                }

        # AbuseIPDB
        abuse_data = osint_data.get("abuseipdb", {})
        if abuse_data:
            abuse_score = abuse_data.get("score", 0)
            if abuse_score > 0:
                abuse_contribution = (abuse_score / 100) * self.weights["abuseipdb_score"]
                score += abuse_contribution
                factors["abuseipdb"] = {
                    "value": abuse_score,
                    "contribution": round(abuse_contribution, 3),
                }

        return score, factors

    def _score_behavioral(self, behavioral_data: dict) -> tuple[float, dict]:
        """Score based on behavioral analysis."""
        score = 0.0
        factors = {}

        # Beacon score
        beacon_score = behavioral_data.get("beacon_score", 0)
        if beacon_score > 0:
            beacon_contribution = beacon_score * self.weights["beacon_score"]
            score += beacon_contribution
            factors["beacon_score"] = {
                "value": round(beacon_score, 2),
                "contribution": round(beacon_contribution, 3),
            }

        # Connection count (normalize to 0-1, cap at 100)
        conn_count = behavioral_data.get("connection_count", 0)
        if conn_count > 0:
            normalized_count = min(conn_count / 100, 1.0)
            conn_contribution = normalized_count * self.weights["connection_count"]
            score += conn_contribution
            factors["connection_count"] = {
                "value": conn_count,
                "contribution": round(conn_contribution, 3),
            }

        # Data volume (normalize, cap at 100MB)
        data_volume = behavioral_data.get("data_volume", 0)
        if data_volume > 0:
            normalized_volume = min(data_volume / 100_000_000, 1.0)
            volume_contribution = normalized_volume * self.weights["data_volume"]
            score += volume_contribution
            factors["data_volume"] = {
                "value": f"{data_volume / 1_000_000:.1f} MB",
                "contribution": round(volume_contribution, 3),
            }

        return score, factors

    def _score_context(self, context_data: dict) -> tuple[float, dict]:
        """Score based on context signals."""
        score = 0.0
        factors = {}

        # JA3 malware match
        ja3_match = context_data.get("ja3_malware_match")
        if ja3_match:
            ja3_contribution = self.weights["ja3_malware_match"]
            score += ja3_contribution
            factors["ja3_malware_match"] = {
                "value": ja3_match,
                "contribution": round(ja3_contribution, 3),
            }

        # DGA match
        dga_match = context_data.get("dga_match", False)
        if dga_match:
            dga_contribution = self.weights["dga_match"]
            score += dga_contribution
            factors["dga_match"] = {
                "value": True,
                "contribution": round(dga_contribution, 3),
            }

        # Self-signed cert
        self_signed = context_data.get("self_signed_cert", False)
        if self_signed:
            cert_contribution = self.weights["self_signed_cert"]
            score += cert_contribution
            factors["self_signed_cert"] = {
                "value": True,
                "contribution": round(cert_contribution, 3),
            }

        return score, factors

    def _get_priority_label(self, score: float) -> str:
        """Get priority label from score using instance thresholds."""
        if score >= self.thresholds["critical"]:
            return "critical"
        elif score >= self.thresholds["high"]:
            return "high"
        elif score >= self.thresholds["medium"]:
            return "medium"
        else:
            return "low"

    def _generate_recommendation(self, score: float, factors: dict, ioc_type: str) -> str:
        """Generate actionable recommendation based on score and factors."""
        if score >= 0.8:
            action = "Immediate block recommended"
        elif score >= 0.6:
            action = "Block and investigate"
        elif score >= 0.4:
            action = "Monitor and investigate"
        else:
            action = "Continue monitoring"

        # Add specific details based on factors
        details = []
        if "vt_detections" in factors and factors["vt_detections"]["contribution"] > 0.1:
            details.append("VirusTotal flagged")
        if "greynoise" in factors and factors["greynoise"]["value"] == "malicious":
            details.append("known malicious IP")
        if "beacon_score" in factors and factors["beacon_score"]["contribution"] > 0.1:
            details.append("C2 beaconing detected")
        if "ja3_malware_match" in factors:
            details.append(f"matches {factors['ja3_malware_match']['value']}")

        if details:
            return f"{action} ({', '.join(details)})"
        return action

    def rank_iocs(
        self,
        iocs: list[dict],
        osint: dict | None = None,
        beacon_results: list | None = None,
    ) -> list[ScoredIOC]:
        """
        Score and rank a list of IOCs.

        Args:
            iocs: List of IOC dicts with 'type' and 'value'
            osint: OSINT data by IP/domain
            beacon_results: Beacon analysis results

        Returns:
            List of ScoredIOC sorted by priority (highest first)
        """
        osint = osint or {}
        beacon_results = beacon_results or []

        # Build behavioral data lookup
        beacon_lookup = {}
        for b in beacon_results:
            if isinstance(b, dict):
                dst = b.get("dst", "")
                if dst:
                    beacon_lookup[dst] = b.get("score", 0)

        scored_iocs = []

        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            ioc_value = ioc.get("value", "")

            # Get OSINT data
            osint_data = {}
            if ioc_type == "ip":
                osint_data = osint.get("ips", {}).get(ioc_value, {})
            elif ioc_type == "domain":
                osint_data = osint.get("domains", {}).get(ioc_value, {})
            elif ioc_type == "ja3":
                ja3_info = osint.get("ja3", {}).get(ioc_value, {})
                if ja3_info.get("malware"):
                    # Synthetic OSINT score for known JA3 malware fingerprint
                    osint_data = {
                        "virustotal": {
                            "detections": JA3_MALWARE_DEFAULT_DETECTIONS,
                            "total": VT_DEFAULT_TOTAL_ENGINES,
                        }
                    }

            # Get behavioral data
            behavioral_data = {
                "beacon_score": beacon_lookup.get(ioc_value, 0),
            }

            # Get context data
            context_data = {}
            if ioc_type == "ja3":
                ja3_info = osint.get("ja3", {}).get(ioc_value, {})
                if ja3_info.get("malware"):
                    context_data["ja3_malware_match"] = ja3_info.get("client", "malware")

            scored = self.score_ioc(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                osint_data=osint_data,
                behavioral_data=behavioral_data,
                context_data=context_data,
            )
            scored_iocs.append(scored)

        # Sort by priority score (highest first)
        scored_iocs.sort(key=lambda x: x.priority_score, reverse=True)

        return scored_iocs

    def explain_score(self, scored_ioc: ScoredIOC) -> str:
        """Generate human-readable explanation of score."""
        lines = [
            f"IOC: {scored_ioc.value} ({scored_ioc.ioc_type})",
            f"Priority: {scored_ioc.priority_label.upper()} ({scored_ioc.priority_score:.1%})",
            "",
            "Contributing factors:",
        ]

        for factor_name, factor_data in sorted(
            scored_ioc.factors.items(), key=lambda x: x[1].get("contribution", 0), reverse=True
        ):
            contribution = factor_data.get("contribution", 0)
            value = factor_data.get("value", "")
            if contribution > 0:
                lines.append(f"  - {factor_name}: {value} (+{contribution:.1%})")

        lines.append("")
        lines.append(f"Recommendation: {scored_ioc.recommendation}")

        return "\n".join(lines)
