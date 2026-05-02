from typing import Dict
from app.models.investigation import InvestigationRecord

# simple in-memory store (Phase 4 → Redis/DB)
INVESTIGATION_DB: Dict[str, InvestigationRecord] = {}


def save_investigation(record: InvestigationRecord):
    INVESTIGATION_DB[record.investigation_id] = record


def get_investigation(investigation_id: str):
    return INVESTIGATION_DB.get(investigation_id)


def list_investigations():
    return list(INVESTIGATION_DB.values())