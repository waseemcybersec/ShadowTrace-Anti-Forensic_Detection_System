from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TimestampSnapshot:
    created: Optional[str]
    modified: Optional[str]
    accessed: Optional[str]
    changed: Optional[str]


@dataclass
class AnalysisFinding:
    module: str
    artifact: str
    severity: str
    status: str
    confidence: int
    rules: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    case_name: str
    examiner: str
    image_path: str
    module: str
    findings: List[AnalysisFinding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
