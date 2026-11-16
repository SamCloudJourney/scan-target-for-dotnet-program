#!/usr/bin/env python3
"""Third-pass downstream analysis: only local ASP.NET, HAProxy, and local receiver."""
import argparse
import http.client
import http.cookiejar
import http.server
import json
import threading
import urllib.request
from urllib.parse import urljoin, urlsplit

HOST = "127.0.0.1"
APP = 5100
RAW_PROXY = 5102
DECODED_PROXY = 5104
RECEIVER = 5103
receiver_hits = []
results = {}
checks = {}

class Receiver(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        receiver_hits.append({"path": self.path, "host": self.headers.get("Host"),
                              "referer": self.headers.get("Referer")})
        body = b"SECOND-LOOPBACK-ORIGIN-RECEIVED"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

def fetch(target, port=APP, headers=None, method="GET"):
    assert port in (APP, RAW_PROXY, DECODED_PROXY, RECEIVER), "nonlocal port not permitted"
    conn = http.client.HTTPConnection(HOST, port, timeout=8)
    conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", f"{HOST}:{port}")
    conn.putheader("Connection", "close")
    for k, v in (headers or {}).items():
        conn.putheader(k, v)
    conn.endheaders()
    resp = conn.getresponse()
    data = {
        "request_target": target,
        "method": method,
        "port": port,
        "status": resp.status,
        "headers": {k.lower(): v for k, v in resp.getheaders()},
        "body": resp.read().decode("utf-8", "replace"),
    }
    conn.close()
    return data

def passed(name, condition):
    checks[name] = bool(condition)

def follow_location(location):
    if not location:
        return {"error": "no-location"}
    url = urljoin(f"http://{HOST}:{APP}/legacy/", location)
    dest = urlsplit(url)
    if dest.scheme != "http" or dest.hostname != HOST or dest.port not in (APP, RECEIVER):
        return {"error": "non-loopback-blocked", "url": url}
    out = fetch(dest.path + ("?" + dest.query if dest.query else ""), dest.port)
    return {"url": url, "port": dest.port, "response": out}

def cookie_jar_case():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(
        f"http://{HOST}:{APP}/cookie/issue?user=alice",
        headers={"X-Forwarded-Prefix": "/;Domain=example.test"})
    with opener.open(request, timeout=8) as response:
        set_cookie = response.headers.get("Set-Cookie")
        status = response.status
    stored = [
        {"name": x.name, "domain": x.domain, "path": x.path,
         "secure": x.secure, "domain_specified": x.domain_specified}
        for x in jar
    ]
    variants = {}
    for path in ("/whoami", "/%3BDomain=example.test/whoami",
                 "/;Domain=example.test/whoami"):
        req = urllib.request.Request(f"http://{HOST}:{APP}" + path)
        jar.add_cookie_header(req)
        value = req.get_header("Cookie")
        variants[path] = {"sent_session_cookie": bool(value), "cookie_names":
                          [c.split("=", 1)[0] for c in (value or "").split("; ") if c]}
    return {"status": status, "header": set_cookie,
            "stored_cookies": stored, "path_scope_decisions": variants,
            "client": "Python stdlib CookieJar — not a browser"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--major", type=int, choices=(10, 11), required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    server = http.server.ThreadingHTTPServer((HOST, RECEIVER), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # #4: Interpret issued cookie in a standards-oriented cookie jar and
        # differentiate cookie Path scope from attempted Domain injection.
        results["cookie_jar"] = cookie_jar_case()
        cj = results["cookie_jar"]
        passed("cookie_jar_received_cookie", cj["status"] == 200 and len(cj["stored_cookies"]) >= 1)
        passed("cookie_jar_no_foreign_domain", all(
            c["domain"].strip(".") == HOST for c in cj["stored_cookies"]))
        passed("cookie_jar_does_not_send_path_restricted_cookie_to_root",
            not cj["path_scope_decisions"]["/whoami"]["sent_session_cookie"])

        # #5/#6: Distinct public representations use different Content-Type,
        # Content-Disposition and frame policy. Collision may taint them all.
        for mode in ("output", "response"):
            name = f"/cache/format-{mode}"
            seed = fetch(name + "?a=B%3D")
            second = fetch(name + "?a=B%3D")
            victim = fetch(name + "?a%3DB=")
            real_b_control = fetch(name + "?a=irrelevant&a%3DB=")
            results[mode + "_format"] = {
                "seed_A": seed, "repeated_A": second,
                "victim_B_collision": victim, "other_request_control": real_b_control}
            expected_collision = mode == "output" or args.major == 10
            passed(mode + "_seed_html",
                   seed["status"] == 200 and
                   seed["headers"].get("content-type", "").startswith("text/html") and
                   "PUBLIC-A" in seed["body"])
            passed(mode + "_repeat_cached", second["body"] == seed["body"])
            passed(mode + "_victim_format_version",
                   (victim["headers"].get("content-type", "").startswith("text/html"))
                   == expected_collision)
            passed(mode + "_victim_disposition_version",
                   (victim["headers"].get("content-disposition") == "inline")
                   == expected_collision)
            passed(mode + "_victim_frame_policy_version",
                   (victim["headers"].get("x-frame-options") == "DENY")
                   == expected_collision)
            passed(mode + "_victim_body_version",
                   ("PUBLIC-A" in victim["body"]) == expected_collision)

        # #7: request includes a synthetic benign marker; confirm when the
        # redirect sends that query to a second loopback origin.
        target = "/legacy//127.0.0.1:5103/received?audit_marker=PUBLIC-FIXTURE"
        red = fetch(target)
        resolved = follow_location(red["headers"].get("location"))
        results["redirect_query_propagation"] = {"request": red, "followed": resolved}
        is_cross_origin = resolved.get("port") == RECEIVER
        passed("rewrite_second_origin_by_version", is_cross_origin == (args.major == 10))
        passed("rewrite_query_marker_version", 
               (len(receiver_hits) == 1 and
                "audit_marker=PUBLIC-FIXTURE" in receiver_hits[0]["path"])
               == (args.major == 10))

        # #8: enumerate only a small fixed set of locally generated path forms
        # to determine whether defenses are robust beyond the original %2F.
        candidate_paths = {
            "slash_upper": "/gate%2Fprivate-document",
            "slash_lower": "/gate%2fprivate-document",
            "encoded_g_and_slash": "/%67ate%2Fprivate-document",
            "double_encoded_slash": "/gate%252Fprivate-document",
            "plain_dot_segments": "/public/../gate/private-document",
            "encoded_dot_segments": "/public/%2e%2e/gate/private-document",
            "dot_plus_encoded_slash": "/public/../gate%2Fprivate-document",
            "canonical": "/gate/private-document",
        }
        matrix = {}
        for label, path in candidate_paths.items():
            row = {}
            for proxy_label, port in (("raw", RAW_PROXY), ("decoded", DECODED_PROXY)):
                target = f"http://{HOST}:{port}{path}"
                row[proxy_label] = fetch(target, port=port)
            matrix[label] = row
        results["proxy_normalization_matrix"] = matrix
        passed("proxy_canonical_blocked_by_both", all(
            matrix["canonical"][k]["status"] == 403 for k in ("raw", "decoded")))
        passed("proxy_original_encoded_slash_version",
            (matrix["slash_upper"]["raw"]["status"] == 200) == (args.major == 10))
        passed("proxy_decode_rule_blocks_original_case",
            matrix["slash_upper"]["decoded"]["status"] == 403)
        results["proxy_normalization_summary"] = {
            "raw_unexpected_successes": [
                label for label, row in matrix.items()
                if row["raw"]["status"] == 200 and label != "canonical"],
            "decoded_unexpected_successes": [
                label for label, row in matrix.items()
                if row["decoded"]["status"] == 200 and label != "canonical"],
            "interpretation": "Any 200 is a synthetic proxy-policy counterexample, NOT application authentication bypass."
        }

    except Exception as exc:
        results["harness_exception"] = {"type": type(exc).__name__, "error": str(exc)}
        passed("harness_completed", False)
    finally:
        server.shutdown()
        server.server_close()
    data = {"framework": f"ASP.NET Core {args.major}.0", "checks": checks,
            "passed": sum(checks.values()), "total": len(checks),
            "failed": [k for k, v in checks.items() if not v],
            "results": results, "receiver_hits": receiver_hits}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(json.dumps({
        "framework": data["framework"], "passed": data["passed"],
        "total": data["total"], "failed": data["failed"],
        "cookie_jar": data["results"].get("cookie_jar"),
        "proxy_summary": data["results"].get("proxy_normalization_summary"),
        "redirect": data["results"].get("redirect_query_propagation"),
        "format_victim_output": data["results"].get("output_format", {}).get("victim_B_collision"),
        "format_victim_response": data["results"].get("response_format", {}).get("victim_B_collision"),
    }, indent=2))
    return 0 if all(checks.values()) else 1

if __name__ == "__main__":
    raise SystemExit(main())
