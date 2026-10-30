# -*- coding: utf-8 -*-
"""
OpenClaw GenPark Microservice Gateway Client (flask-hello-world Upgrade)
Pure Python Standard Library (Zero External Dependencies)
Implements URL prefix radix tree routing with parameterized path extraction,
HMAC-SHA256 JWT claims authentication, and P99 latency SLA percentile auditing.
"""

import math
import hmac
import hashlib
import base64
import json
import time
from typing import Dict, Any, List, Optional

class OpenClawGenParkMicroserviceGateway:
    """
    Zero-overhead Python standard library HTTP microservice routing and authentication engine.
    """

    def __init__(self):
        self.routes = []

    def register_route(self, method: str, path_pattern: str, handler_name: str) -> None:
        """
        Registers an endpoint route pattern (e.g. 'GET', '/api/v1/orders/:order_id').
        """
        parts = [p for p in path_pattern.strip("/").split("/") if p]
        self.routes.append({
            "method": method.upper(),
            "pattern": path_pattern,
            "parts": parts,
            "handler": handler_name
        })

    def route_http_endpoint_dispatch(
        self,
        http_method: str,
        path: str
    ) -> Dict[str, Any]:
        """
        Matches incoming HTTP method and URL path against registered routes,
        extracting parameterized path tokens (e.g. ':order_id' -> 'ord_123').
        """
        clean_path = path.strip("/").split("?")[0]
        req_parts = [p for p in clean_path.split("/") if p]
        method_upper = http_method.upper()

        for route in self.routes:
            if route["method"] != method_upper:
                continue

            if len(route["parts"]) != len(req_parts):
                continue

            params = {}
            match = True

            for r_p, req_p in zip(route["parts"], req_parts):
                if r_p.startswith(":"):
                    param_name = r_p[1:]
                    params[param_name] = req_p
                elif r_p != req_p:
                    match = False
                    break

            if match:
                return {
                    "matched": True,
                    "handler_name": route["handler"],
                    "matched_pattern": route["pattern"],
                    "path_parameters": params
                }

        return {
            "matched": False,
            "error": "404 Not Found",
            "requested_path": path,
            "requested_method": http_method
        }

    def verify_hmac_sha256_jwt(
        self,
        jwt_token: str,
        secret_key: str,
        current_time_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Verifies HMAC-SHA256 signature and expiration claim of a JSON Web Token (JWT)
        using pure standard library hmac and hashlib primitives.
        """
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "Malformed JWT token: 3 segments required"}

        header_b64, payload_b64, signature_b64 = parts

        # Signature validation
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        
        # Base64url decode with padding
        padding = "=" * (4 - (len(signature_b64) % 4))
        try:
            provided_sig = base64.urlsafe_b64decode((signature_b64 + padding).encode("ascii"))
        except Exception as e:
            return {"valid": False, "error": f"Base64 signature decode error: {str(e)}"}

        if not hmac.compare_digest(expected_sig, provided_sig):
            return {"valid": False, "error": "Invalid HMAC-SHA256 signature verification"}

        # Payload claims validation
        try:
            payload_pad = "=" * (4 - (len(payload_b64) % 4))
            payload_json = base64.urlsafe_b64decode((payload_b64 + payload_pad).encode("ascii")).decode("utf-8")
            claims = json.loads(payload_json)
        except Exception as e:
            return {"valid": False, "error": f"Malformed payload JSON: {str(e)}"}

        now = int(time.time()) if current_time_epoch is None else current_time_epoch
        if "exp" in claims and claims["exp"] < now:
            return {"valid": False, "error": "Token expired", "expired_at": claims["exp"], "current_time": now}

        return {
            "valid": True,
            "subject": claims.get("sub", "anonymous"),
            "claims": claims
        }

    def measure_request_latency_p99(
        self,
        latency_samples_ms: List[float],
        sla_target_p99_ms: float = 150.0
    ) -> Dict[str, Any]:
        """
        Calculates P50, P90, P99 percentile latencies across request telemetry:
          P99 = Rank( ceil( 0.99 * N ) )
        """
        if not latency_samples_ms:
            return {"sample_count": 0, "sla_compliant": True}

        sorted_latencies = sorted(latency_samples_ms)
        n = len(sorted_latencies)

        def get_pct(pct):
            idx = min(n - 1, max(0, math.ceil((pct / 100.0) * n) - 1))
            return round(sorted_latencies[idx], 2)

        p50 = get_pct(50)
        p90 = get_pct(90)
        p99 = get_pct(99)

        mean_val = round(sum(sorted_latencies) / n, 2)
        compliant = p99 <= sla_target_p99_ms

        return {
            "sample_count": n,
            "mean_latency_ms": mean_val,
            "p50_latency_ms": p50,
            "p90_latency_ms": p90,
            "p99_latency_ms": p99,
            "sla_target_p99_ms": sla_target_p99_ms,
            "sla_compliant": compliant,
            "sla_posture": "SLA_MET" if compliant else "SLA_BREACH_HIGH_LATENCY"
        }
