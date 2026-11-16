#!/usr/bin/env python3
"""Loopback-only behavior tests. No external targets or actual credentials."""
import argparse
import http.client
import json
import re
import socket
import threading
import time
from urllib.parse import urlsplit

HOST = "127.0.0.1"
BACKEND = 5089
PROXY = 5090
samples = {}
proxy_log = []

def exchange(target, headers=None, port=BACKEND):
    conn = http.client.HTTPConnection(HOST, port, timeout=8)
    conn.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", f"{HOST}:{BACKEND}")
    conn.putheader("Connection", "close")
    for key, value in (headers or {}).items():
        conn.putheader(key, value)
    conn.endheaders()
    res = conn.getresponse()
    content = res.read().decode("utf-8", errors="replace")
    result = {
        "request_target": target,
        "status": res.status,
        "body": content,
        "location": res.getheader("Location"),
        "set_cookie": res.getheader("Set-Cookie"),
        "cache_control": res.getheader("Cache-Control"),
        "via": "local-proxy" if port == PROXY else "direct",
    }
    conn.close()
    return result

def listen_proxy(ready):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PROXY))
    server.listen(16)
    server.settimeout(1)
    ready.set()
    while True:
        try:
            client, _ = server.accept()
        except socket.timeout:
            if STOP.is_set():
                break
            continue
        with client:
            client.settimeout(5)
            req = b""
            while b"\r\n\r\n" not in req and len(req) < 16384:
                data = client.recv(16384)
                if not data:
                    break
                req += data
            if b"\r\n\r\n" not in req:
                continue
            parts = req.split(b"\r\n", 1)[0].decode("ascii", "replace").split(" ")
            if len(parts) < 3:
                continue
            target = parts[1]
            parsed_path = urlsplit(target).path if "://" in target else target.split("?", 1)[0]
            blocked = parsed_path.startswith("/gate/")
            proxy_log.append({"target": target, "policy_seen_path": parsed_path, "blocked": blocked})
            if blocked:
                body = b"UPSTREAM-DENIED"
                client.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body)
                continue
            with socket.create_connection((HOST, BACKEND), timeout=5) as upstream:
                upstream.sendall(req)
                while True:
                    packet = upstream.recv(16384)
                    if not packet:
                        break
                    client.sendall(packet)
    server.close()

def capture(name, target, headers=None, via_proxy=False):
    samples[name] = exchange(target, headers, PROXY if via_proxy else BACKEND)

def audit(major):
    checks = {}
    def check(name, ok):
        checks[name] = bool(ok)
    c = samples["cookie_prefix"]["set_cookie"] or ""
    check("cookie_pathbase_from_trusted_hop", "pathbase=/;Domain=example.test" in samples["cookie_prefix"]["body"])
    check("cookie_domain_attribute_version_behavior",
          bool(re.search(r";\s*Domain=example\.test(?:;|$)", c, re.I)) == (major == 10))
    check("cookie_invalid_prefix_rejected",
          samples["cookie_invalid"]["body"] == "pathbase=")
    check("output_first_response_cached",
          samples["output_a"]["body"] == samples["output_a_repeat"]["body"])
    check("output_distinct_shapes_collide",
          samples["output_a"]["body"] == samples["output_b"]["body"])
    check("output_noncolliding_control",
          samples["output_a"]["body"] != samples["output_c"]["body"])
    check("output_set_cookie_not_cached",
          samples["output_cookie_a"]["body"] != samples["output_cookie_repeat"]["body"])
    check("response_first_response_cached",
          samples["response_a"]["body"] == samples["response_a_repeat"]["body"])
    check("response_collision_fixed_v11",
          (samples["response_a"]["body"] == samples["response_b"]["body"]) == (major == 10))
    check("response_noncolliding_control",
          samples["response_a"]["body"] != samples["response_c"]["body"])
    check("rewrite_local_control",
          (samples["rewrite_local"]["location"] or "").startswith("/safe"))
    loc = samples["rewrite_attack"]["location"] or ""
    check("rewrite_leading_slash_fix_v11",
          loc.startswith("//evil.example") if major == 10
          else loc.startswith("/evil.example") and not loc.startswith("//"))
    check("origin_encoded_slash_not_routed",
          samples["kestrel_origin"]["status"] == 404)
    check("absolute_encoded_slash_version_behavior",
          (samples["kestrel_absolute"]["status"] == 200) == (major == 10))
    check("canonical_route_control",
          samples["kestrel_canonical"]["status"] == 200)
    check("app_authorization_not_bypassed",
          samples["kestrel_auth_absolute"]["status"] != 200)
    check("upstream_policy_rejects_canonical",
          samples["proxy_canonical"]["status"] == 403)
    check("upstream_decoding_mismatch_version_behavior",
          (samples["proxy_absolute_encoded"]["status"] == 200) == (major == 10))
    check("proxy_origin_encoded_not_routed",
          samples["proxy_origin_encoded"]["status"] == 404)
    return checks

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--major", type=int, required=True, choices=(10, 11))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ready = threading.Event()
    threading.Thread(target=listen_proxy, args=(ready,), daemon=True).start()
    if not ready.wait(5):
        raise RuntimeError("Proxy failed to start")
    try:
        capture("cookie_plain", "/cookie")
        capture("cookie_prefix", "/cookie", {"X-Forwarded-Prefix": "/;Domain=example.test"})
        capture("cookie_invalid", "/cookie", {"X-Forwarded-Prefix": "not-an-absolute-path"})
        for prefix in ("output", "response"):
            capture(prefix + "_a", f"/{prefix}?a=B%3D")
            capture(prefix + "_a_repeat", f"/{prefix}?a=B%3D")
            capture(prefix + "_b", f"/{prefix}?a%3DB=")
            capture(prefix + "_c", f"/{prefix}?a=B")
        capture("output_cookie_a", "/output-cookie?a=B%3D")
        capture("output_cookie_repeat", "/output-cookie?a=B%3D")
        capture("rewrite_local", "/legacy/safe")
        capture("rewrite_attack", "/legacy//evil.example")
        capture("kestrel_origin", "/gate%2Fsecret")
        capture("kestrel_absolute", f"http://{HOST}:{BACKEND}/gate%2Fsecret")
        capture("kestrel_canonical", "/gate/secret")
        capture("kestrel_auth_absolute", f"http://{HOST}:{BACKEND}/auth%2Fsecret")
        capture("proxy_canonical", "/gate/secret", via_proxy=True)
        capture("proxy_absolute_encoded", f"http://{HOST}:{BACKEND}/gate%2Fsecret", via_proxy=True)
        capture("proxy_origin_encoded", "/gate%2Fsecret", via_proxy=True)
        checks = audit(args.major)
    except Exception as exc:
        checks = {"harness_error": False}
        samples["harness_error"] = {"error": str(exc)}
    finally:
        STOP.set()
    evidence = {
        "framework": f"net{args.major}.0",
        "requests": samples,
        "proxy_decisions": proxy_log,
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks)
    }
    with open(args.output, "w") as f:
        json.dump(evidence, f, indent=2)
    print(json.dumps({"framework": evidence["framework"], "checks": checks, "failed": [k for k,v in checks.items() if not v]}, indent=2))
    return 0 if all(checks.values()) else 1

STOP = threading.Event()
if __name__ == "__main__":
    raise SystemExit(main())
