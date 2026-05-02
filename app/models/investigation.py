from datetime import datetime
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uuid


class InvestigationRecord(BaseModel):
    investigation_id: str
    ioc:        str
    ioc_type:   str
    timestamp:  datetime
    verdict:    str
    score:      float
    raw_score:  float = 0
    confidence: float
    sources:    Dict[str, Any] = {}
    geo:        Dict[str, Any] = {}
    mitre_tactics: List[Any]   = []
    owasp:      List[Any]      = []
    tags:       List[str]      = []
    pivots:     List[str]      = []
    summary:    str            = ""
    narrative:  str            = ""
    ai_analysis: str           = ""
    links:      Dict[str, Any] = {}


def generate_investigation_id() -> str:
    return f"INV-{uuid.uuid4().hex[:12].upper()}"