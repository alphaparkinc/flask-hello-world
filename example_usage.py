# -*- coding: utf-8 -*-
from client import OpenClawGenParkMicroserviceGateway
import base64
import hmac
import hashlib
import json

gw = OpenClawGenParkMicroserviceGateway()

# Register routes
gw.register_route("GET", "/api/v1/orders/:order_id", "get_order_details")
gw.register_route("POST", "/api/v1/escrow/release", "release_escrow")

# 1. Parameterized Routing
req = gw.route_http_endpoint_dispatch("GET", "/api/v1/orders/ord_9901")
print(f"HTTP Route Dispatch: Matched={req['matched']} -> {req['handler_name']}")
print(f"  Extracted Params: {req['path_parameters']}")

# 2. JWT HMAC-SHA256 Verification
secret = "super_secret_openclaw_key_2026"
header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
payload = base64.urlsafe_b64encode(json.dumps({"sub": "agent_alpha", "role": "buyer", "exp": 2000000000}).encode()).decode().rstrip("=")
sig_raw = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
sig = base64.urlsafe_b64encode(sig_raw).decode().rstrip("=")
valid_token = f"{header}.{payload}.{sig}"

auth = gw.verify_hmac_sha256_jwt(valid_token, secret)
print()
print(f"JWT Verification: Valid={auth['valid']} (Subject: {auth.get('subject')})")

# 3. Latency P99 SLA
latencies = [12.4, 15.2, 18.0, 19.5, 22.1, 28.3, 35.0, 48.2, 85.0, 142.0]
sla = gw.measure_request_latency_p99(latencies, sla_target_p99_ms=150.0)
print()
print(f"Latency SLA: Mean={sla['mean_latency_ms']}ms, P99={sla['p99_latency_ms']}ms ({sla['sla_posture']})")
