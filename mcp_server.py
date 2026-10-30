# -*- coding: utf-8 -*-
"""
OpenClaw GenPark Microservice Gateway MCP Server
FastMCP standard interface for HTTP endpoint routing, JWT HMAC-SHA256 authentication, and P99 latency SLA checks.
"""

import json
from typing import Dict, Any, List, Optional
from client import OpenClawGenParkMicroserviceGateway

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("flask-hello-world")
except ImportError:
    class MockFastMCP:
        def __init__(self, name):
            self.name = name
        def tool(self):
            def decorator(f):
                return f
            return decorator
    mcp = MockFastMCP("flask-hello-world")

gw = OpenClawGenParkMicroserviceGateway()
gw.register_route("GET", "/api/v1/health", "health_check")
gw.register_route("GET", "/api/v1/users/:user_id", "get_user")
gw.register_route("POST", "/api/v1/checkout/:cart_id", "process_checkout")

@mcp.tool()
def route_http_endpoint_dispatch(
    http_method: str,
    path: str
) -> str:
    """
    Matches incoming HTTP method and URL path against registered routes.
    """
    res = gw.route_http_endpoint_dispatch(http_method, path)
    return json.dumps(res, indent=2)

@mcp.tool()
def verify_hmac_sha256_jwt(
    jwt_token: str,
    secret_key: str
) -> str:
    """
    Verifies HMAC-SHA256 signature and expiration claim of a JSON Web Token.
    """
    res = gw.verify_hmac_sha256_jwt(jwt_token, secret_key)
    return json.dumps(res, indent=2)

@mcp.tool()
def measure_request_latency_p99(
    latency_samples_ms: List[float],
    sla_target_p99_ms: float = 150.0
) -> str:
    """
    Calculates P50, P90, P99 percentile latencies across request telemetry.
    """
    res = gw.measure_request_latency_p99(latency_samples_ms, sla_target_p99_ms)
    return json.dumps(res, indent=2)

def main():
    print("Testing Gateway:")
    print(route_http_endpoint_dispatch("GET", "/api/v1/users/usr_4812"))

if __name__ == "__main__":
    main()
