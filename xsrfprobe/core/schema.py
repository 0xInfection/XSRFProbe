from enum import Enum
from pydantic import BaseModel

class TokenDiscoveryPartEnum(Enum):
    RESPONSE_BODY = "response_body"  # only for passive mode
    REQUEST_QUERY = "request_query"
    REQUEST_BODY = "request_body"
    RESPONSE_HEADERS = "response_headers"
    COOKIE = "cookie"

class TokenDiscoveryModeEnum(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"

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
