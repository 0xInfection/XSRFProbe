from enum import Enum
from pydantic import BaseModel


class TokenDiscoveryPartEnum(Enum):
    RESPONSE_BODY = "response_body"
    REQUEST_QUERY = "request_query"
    REQUEST_BODY = "request_body"
    RESPONSE_HEADERS = "response_headers"
    COOKIE = "cookie"


class TokenDiscoveryModeEnum(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DiscoveredToken(BaseModel):
    name: str
    token: str
    url: str
    mode: TokenDiscoveryModeEnum
    discovery_part: TokenDiscoveryPartEnum


class BenchmarkResult(BaseModel):
    base_benchmark: list[str]
    status_code: int
    headers: dict
    # False when a plain page load is indistinguishable from a successful
    # submission (e.g. SPA shells) — body-diff-based bypass tests are unreliable.
    discriminative: bool = True
    # Per-endpoint pass threshold, auto-calibrated from how similar the baseline
    # samples are to each other (their own match against the consolidated
    # template). Stable pages get a stricter bar, dynamic pages a looser one.
    similarity_threshold: float = 90.0


class Finding(BaseModel):
    test_id: str = ""
    description: str
    severity: SeverityEnum = SeverityEnum.MEDIUM
    details: dict = {}
    poc_paths: list[str] = []


class UrlFindings(BaseModel):
    url: str
    findings: list[Finding] = []


class ScanReport(BaseModel):
    target_url: str
    scan_duration_seconds: float = 0.0
    urls_scanned: int = 0
    forms_tested: int = 0
    vulnerabilities: list[UrlFindings] = []
    tokens_discovered: list[DiscoveredToken] = []
    strengths: list[str] = []
