#!/usr/bin/env python3
"""Loopback-only downstream consequence tests for authorized ASP.NET Core research."""
import argparse
import http.client
import http.server
import json
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

HOST="127.0.0.1"
APP=5100
PROXY=5102
HARDENED=5104
RECEIVER=5103
received=[]
checks={}
cases={}

class RedirectReceiver(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        received.append({"path":self.path,"host":self.headers.get("Host")})
        body=b"LOCAL-SECOND-ORIGIN-REACHED"
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):
        return

def get(target, headers=None, port=APP, source_ip=HOST):
    conn=http.client.HTTPConnection(HOST,port,timeout=8,source_address=(source_ip,0))
    conn.putrequest("GET",target,skip_host=True,skip_accept_encoding=True)
    conn.putheader("Host",f"{HOST}:{port}")
    conn.putheader("Connection","close")
    for name,value in (headers or {}).items():
        conn.putheader(name,value)
    conn.endheaders()
    res=conn.getresponse()
    headers_out={k.lower():v for k,v in res.getheaders()}
    result={"target":target,"port":port,"status":res.status,
            "body":res.read().decode("utf-8","replace"),
            "location":res.getheader("Location"),
            "set_cookie":res.getheader("Set-Cookie"),
            "cache_control":res.getheader("Cache-Control"),
            "variant":res.getheader("X-Lab-Variant"),
            "headers":headers_out}
    conn.close()
    return result

def ck(name,value):
    checks[name]=bool(value)

def category(resp):
    m=re.search(r"category=(public-[A-Za-z]+)",resp["body"])
    return m.group(1) if m else None

def follow_on_loopback(location):
    if not location:return {"error":"no-location"}
    dest=urljoin(f"http://{HOST}:{APP}/legacy/",location)
    parsed=urlsplit(dest)
    if parsed.hostname!=HOST or parsed.scheme!="http" or parsed.port not in (APP,RECEIVER):
        return {"error":"non-loopback-follow-blocked","url":dest}
    result=get((parsed.path or "/") + ("?"+parsed.query if parsed.query else ""),port=parsed.port)
    return {"resolved_url":dest,"destination_port":parsed.port,"status":result["status"],
            "body":result["body"]}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--major",type=int,choices=(10,11),required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    srv=http.server.ThreadingHTTPServer((HOST,RECEIVER),RedirectReceiver)
    threading.Thread(target=srv.serve_forever,daemon=True).start()
    try:
        # #4: requests accepted only from the configured trusted peer. The raw
        # app-selected CookieOptions.Path is a separate unsafe configuration control.
        for label,prefix in [
            ("semicolon","/;Domain=example.test"),
            ("encoded_semicolon","/%3BDomain=example.test"),
            ("encoded_crlf","/%0D%0ASet-Cookie:fake=1"),
            ("comma","/x,y"),
            ("double_encoded","/%253BDomain=example.test")]:
            cases["cookie_"+label]=get("/cookie/issue?user=alice",{"X-Forwarded-Prefix":prefix})
            c=cases["cookie_"+label]
            ck("cookie_"+label+"_safe",
                c["status"]==200 and
                not bool(re.search(r";\\s*Domain=example\\.test(?:;|$)",c["set_cookie"] or "",re.I))
                and "\\r" not in (c["set_cookie"] or "") and "\\n" not in (c["set_cookie"] or ""))
        cases["cookie_untrusted"]=get("/cookie/issue?user=alice",
            {"X-Forwarded-Prefix":"/;Domain=example.test"},source_ip="127.0.0.2")
        ck("untrusted_forwarded_prefix_ignored",cases["cookie_untrusted"]["body"].endswith("pathbase="))
        cases["antiforgery"]=get("/cookie/antiforgery",{"X-Forwarded-Prefix":"/;Domain=example.test"})
        cases["tempdata"]=get("/cookie/tempdata",{"X-Forwarded-Prefix":"/;Domain=example.test"})
        for k in ("antiforgery","tempdata"):
            ck(k+"_no_separate_domain",not bool(re.search(r";\\s*Domain=example\\.test(?:;|$)",
                    cases[k]["set_cookie"] or "",re.I)))
        cases["raw_explicit_cookie"]=get("/cookie/explicit")
        ck("explicit_application_cookie_control",bool(re.search(
            r";\\s*Domain=example\\.test(?:;|$)",
            cases["raw_explicit_cookie"]["set_cookie"] or "",re.I)))

        # #5/#6: request A is cached, then a second *distinct decoded query pair*
        # requests B. Distinct variants intentionally give different public content.
        for mode in ("output","response"):
            base="/cache/public-"+mode
            cases[mode+"_seed"]=get(base+"?a=B%3D",{"X-Lab-Client":"attacker"})
            time.sleep(0.55)
            cases[mode+"_repeat"]=get(base+"?a=B%3D",{"X-Lab-Client":"victim"})
            time.sleep(0.35)
            cases[mode+"_victim"]=get(base+"?a%3DB=",{"X-Lab-Client":"victim"})
            cases[mode+"_control"]=get(base+"?a=noncollision")
            ck(mode+"_same_request_cached",cases[mode+"_seed"]["body"]==cases[mode+"_repeat"]["body"])
            ck(mode+"_collision_expected_by_version",
               (cases[mode+"_victim"]["body"]==cases[mode+"_seed"]["body"]) ==
                  (mode=="output" or args.major==10))
            ck(mode+"_victim_wrong_public_variant_expected",
               (category(cases[mode+"_victim"])=="public-A") ==
                  (mode=="output" or args.major==10))
            # Injected Authorization should invalidate ordinary public lookup.
            cases[mode+"_authorization_control"]=get(base+"?a=B%3D",
                {"Authorization":"Bearer synthetic-not-real"})
            ck(mode+"_authorization_control_fresh",
               cases[mode+"_authorization_control"]["body"]!=cases[mode+"_seed"]["body"])

        cases["cookie_response_a"]=get("/cache/output-cookie")
        cases["cookie_response_b"]=get("/cache/output-cookie")
        ck("output_set_cookie_not_reused",cases["cookie_response_a"]["body"]!=cases["cookie_response_b"]["body"])

        # Genuine signed fixture cookies for two local identities. The private
        # endpoints are safe cache-policy controls: no cross-user content sharing.
        for user in ("alice","bob"):
            issue=get("/cookie/issue?user="+user)
            cases["issue_"+user]=issue
            token=(issue["set_cookie"] or "").split(";",1)[0]
            for mode in ("output","response"):
                cases["private_"+mode+"_"+user]=get("/cache/private-"+mode,
                    {"Cookie":token})
                ck("private_"+mode+"_"+user+"_identity",
                   "identity="+user in cases["private_"+mode+"_"+user]["body"])
        for mode in ("output","response"):
            cases["private_"+mode+"_anonymous"]=get("/cache/private-"+mode)
            ck("private_"+mode+"_anonymous_denied",
               cases["private_"+mode+"_anonymous"]["status"]==401)
            ck("private_"+mode+"_cross_user_separate",
               cases["private_"+mode+"_alice"]["body"]!=cases["private_"+mode+"_bob"]["body"])

        # #7: follow the emitted scheme-relative Location to a SECOND local origin.
        cases["rewrite_attack"]=get("/legacy//127.0.0.1:5103/receiver")
        cases["rewrite_follow"]=follow_on_loopback(cases["rewrite_attack"]["location"])
        cases["rewrite_control"]=get("/safelegacy//127.0.0.1:5103/receiver")
        cases["rewrite_safe_follow"]=follow_on_loopback(cases["rewrite_control"]["location"])
        ck("rewrite_external_origin_follow_expected",
           (cases["rewrite_follow"].get("destination_port")==RECEIVER)==(args.major==10))
        ck("rewrite_safe_prefix_local",
           cases["rewrite_safe_follow"].get("destination_port")==APP)
        ck("rewrite_local_receiver_count_expected",len(received)==(1 if args.major==10 else 0))

        # #8: one deliberately proxy-only access control, one hardened proxy ACL,
        # and one independent backend authorization boundary.
        protected="/gate/private-document"
        attack=f"http://{HOST}:{PROXY}/gate%2Fprivate-document"
        hardened=f"http://{HOST}:{HARDENED}/gate%2Fprivate-document"
        cases["haproxy_canonical"]=get(protected,port=PROXY)
        cases["haproxy_origin_encoded"]=get("/gate%2Fprivate-document",port=PROXY)
        cases["haproxy_absolute"]=get(attack,port=PROXY)
        cases["haproxy_hardened"]=get(hardened,port=HARDENED)
        cases["haproxy_hardened_canonical"]=get(protected,port=HARDENED)
        cases["haproxy_authorized_route"]=get(
            f"http://{HOST}:{PROXY}/gate%2Fauth-private-document",port=PROXY)
        ck("haproxy_raw_canonical_denied",cases["haproxy_canonical"]["status"]==403)
        ck("haproxy_raw_origin_stays_unrouted",cases["haproxy_origin_encoded"]["status"]==404)
        ck("haproxy_downstream_lab_document_version",
           ("SYNTHETIC-RESTRICTED-DOCUMENT" in cases["haproxy_absolute"]["body"]) ==
           (args.major==10))
        ck("haproxy_hardened_blocks_encoded",
           cases["haproxy_hardened"]["status"]==403)
        ck("haproxy_hardened_blocks_canonical",
           cases["haproxy_hardened_canonical"]["status"]==403)
        ck("app_authorization_still_denies",
           cases["haproxy_authorized_route"]["status"] in (401,404))
    finally:
        srv.shutdown()
        srv.server_close()
    data={"framework":f"net{args.major}.0","scope":"loopback fixture only",
          "cases":cases,"redirect_receiver":received,
          "checks":checks,"passed":sum(checks.values()),"total":len(checks),
          "failures":[key for key,ok in checks.items() if not ok]}
    with open(args.output,"w") as f:json.dump(data,f,indent=2)
    print(json.dumps({"framework":data["framework"],"passed":data["passed"],
          "total":data["total"],"failures":data["failures"],
          "impact_cases":{k:{"status":v.get("status"),"body":v.get("body"),
              "location":v.get("location")} for k,v in cases.items()
              if k in ("output_victim","response_victim","rewrite_attack",
                        "haproxy_absolute","haproxy_hardened","haproxy_authorized_route")}},
          indent=2))
    return 0 if all(checks.values()) else 1

if __name__=="__main__":
    raise SystemExit(main())
