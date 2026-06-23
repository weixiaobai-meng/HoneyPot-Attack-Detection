"""
Step 1: unified semantic event model for thesis experiments.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
import json


class AlertType(Enum):
    """Supported alert categories."""
    FILE_HONEYPOT = "file"
    ACCOUNT_HONEYPOT = "account"
    PARASITIC_HONEYPOT = "parasitic"
    AUDIT_EVENT = "audit"


@dataclass
class UnifiedAlert:
    """
    Canonical event used by the downstream thesis pipeline.

    The original project started from a light-weight alert schema. This
    structure extends it into a semantic event model so later stages can build
    standard triples and provenance graphs without re-guessing context.
    """

    alert_id: str
    alert_type: AlertType
    timestamp: datetime

    attacker_ip: Optional[str] = None
    attacker_info: Optional[str] = None
    target_host: Optional[str] = None
    target_path: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    process_info: Optional[Dict[str, Any]] = None

    # Canonical semantic fields for thesis-oriented downstream analysis.
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    source_label: Optional[str] = None
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    object_label: Optional[str] = None
    stage: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_canonical_event(self) -> Dict[str, Any]:
        """Serialize as a thesis-friendly canonical event."""
        return {
            "event_id": self.alert_id,
            "event_type": self.alert_type.value,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "source": {
                "type": self.source_type,
                "id": self.source_id,
                "label": self.source_label,
                "ip": self.attacker_ip,
                "info": self.attacker_info,
            },
            "object": {
                "type": self.object_type,
                "id": self.object_id,
                "label": self.object_label,
                "host": self.target_host,
                "path": self.target_path,
            },
            "session_id": self.session_id,
            "process": self.process_info,
            "stage": self.stage,
            "tactic": self.tactic,
            "technique": self.technique,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence or self.details,
            "raw_details": self.details,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Backward-compatible alias used by existing pipeline code."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "timestamp": self.timestamp.isoformat(),
            "attacker_ip": self.attacker_ip,
            "attacker_info": self.attacker_info,
            "target_host": self.target_host,
            "target_path": self.target_path,
            "action": self.action,
            "details": self.details,
            "session_id": self.session_id,
            "process_info": self.process_info,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_label": self.source_label,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "object_label": self.object_label,
            "stage": self.stage,
            "tactic": self.tactic,
            "technique": self.technique,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence": self.evidence,
            "canonical_event": self.to_canonical_event(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)
