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


class VulnerabilityResult(BaseModel):
    url: str
    vuln_type: str
    description: str
    severity: SeverityEnum = SeverityEnum.MEDIUM
    poc_paths: list[str] = []
    details: dict = {}


class ScanReport(BaseModel):
    target_url: str
    scan_duration_seconds: float = 0.0
    urls_scanned: int = 0
    forms_tested: int = 0
    vulnerabilities: list[VulnerabilityResult] = []
    tokens_discovered: list[DiscoveredToken] = []
    strengths: list[str] = []
