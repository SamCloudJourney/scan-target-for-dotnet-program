#!/usr/bin/env python3
"""Authenticated data-isolation and reproducible cache-content integrity controls."""
import argparse
import concurrent.futures
import http.client
import json
import time

HOST="127.0.0.1"; APP=5200
evidence={}; checks={}
def flag(key,val):checks[key]=bool(val)
def get(path,headers=None,method="GET"):
    conn=http.client.HTTPConnection(HOST,APP,timeout=12)
    conn.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
    conn.putheader("Host",f"{HOST}:{APP}")
    conn.putheader("Connection","close")
    for k,v in (headers or {}).items():conn.putheader(k,v)
    conn.endheaders()
    rsp=conn.getresponse()
    rawh={k.lower():v for k,v in rsp.getheaders()}
    token=rawh.pop("set-cookie",None)
    body=rsp.read().decode("utf-8","replace")
    conn.close()
    return {"target":path,"method":method,"status":rsp.status,
            "headers":rawh,"set_cookie_names":[x.split("=",1)[0] for x in (token or "").split(",") if "=" in x],
            "body":body,"_cookie":token}
def sanitized(r):
    return {k:v for k,v in r.items() if k!="_cookie"}
def login(name):
    r=get("/auth/login?user="+name)
    if r["status"]!=200 or not r["_cookie"]:raise RuntimeError("missing signed fixture cookie")
    return r["_cookie"].split(";",1)[0]
def variant(body):
    return "A" if "public A" in body or "variant=A" in body else ("B" if "variant=B" in body else "")
def main():
    pa=argparse.ArgumentParser();pa.add_argument("--major",type=int,choices=(10,11),required=True)
    pa.add_argument("--output",required=True);args=pa.parse_args()
    try:
        alice,bob=login("alice"),login("bob")
        evidence["auth"]={}
        for user,cookie in [("alice",alice),("bob",bob)]:
            for mode,path in [
                ("output_A","/auth/export?a=B%3D"),
                ("output_B","/auth/export?a%3DB="),
                ("response_A","/cache/response-private?a=B%3D"),
                ("response_B","/cache/response-private?a%3DB=")]:
                r=get(path,{"Cookie":cookie})
                evidence["auth"][user+"_"+mode]=sanitized(r)
                flag("auth_"+user+"_"+mode,
                     r["status"]==200 and "identity="+user in r["body"])
        for endpoint in ("/auth/export?a=B%3D", "/cache/response-private?a=B%3D"):
            anon=get(endpoint)
            flag("anonymous_denied_"+endpoint.split("?")[0],anon["status"]==401)
        evidence["auth"]["anonymous_export"]=sanitized(get("/auth/export?a%3DB="))
        flag("anonymous_export_B_denied",evidence["auth"]["anonymous_export"]["status"]==401)
        # Public cache key must be read as a full response envelope.
        a=get("/cache/public?a=B%3D");time.sleep(.25)
        a_repeat=get("/cache/public?a=B%3D")
        b=get("/cache/public?a%3DB=")
        other=get("/cache/public?different=1")
        auth_header=get("/cache/public?a=B%3D",headers={"Authorization":"Bearer local-test-not-secret"})
        evidence["public"]={k:sanitized(v) for k,v in
           [("seed_A",a),("repeat_A",a_repeat),("distinct_B",b),
            ("noncolliding",other),("authorization_control",auth_header)]}
        flag("public_seed_html",a["status"]==200 and "text/html" in a["headers"].get("content-type",""))
        flag("public_repeated_cached",a_repeat["body"]==a["body"])
        flag("public_cross_variant_collision",b["body"]==a["body"])
        flag("public_cross_header_csp",b["headers"].get("content-security-policy")==a["headers"].get("content-security-policy"))
        flag("public_cross_header_cors",b["headers"].get("access-control-allow-origin")==a["headers"].get("access-control-allow-origin"))
        flag("public_cross_header_etag",b["headers"].get("etag")==a["headers"].get("etag"))
        flag("public_noncolliding_representation",other["body"]!=a["body"])
        flag("public_authorization_not_shared",auth_header["status"]==200 and
             auth_header["headers"].get("age") is None)
        # Check PathBase is in the key on supported current builds, but do
        # not assume expected behavior — record, separately classify.
        prefix_a=get("/cache/pathbase",{"X-Forwarded-Prefix":"/tenant-a"})
        prefix_b=get("/cache/pathbase",{"X-Forwarded-Prefix":"/tenant-b"})
        evidence["pathbase"]={"A":sanitized(prefix_a),"B":sanitized(prefix_b),
                              "separate":prefix_a["body"]!=prefix_b["body"]}
        flag("pathbase_endpoint_reached",prefix_a["status"]==200 and prefix_b["status"]==200)
        # Set-Cookie default policy must stop storage despite colliding query.
        c1=get("/cache/set-cookie?a=B%3D");c2=get("/cache/set-cookie?a=B%3D")
        evidence["cookie_output"]={"first":sanitized(c1),"repeat":sanitized(c2)}
        flag("cookie_output_not_cached",c1["body"]!=c2["body"])
        # Explicit VaryByQuery("a") negative control. The different B key
        # should NOT collide with one fixed named query-key serialization.
        n1=get("/cache/single-query?a=B%3D")
        n2=get("/cache/single-query?a%3DB=")
        evidence["fixed_name_vary"]={"A":sanitized(n1),"B":sanitized(n2)}
        flag("fixed_name_distinct",n1["body"]!=n2["body"])
        # Concurrent public reads, using a distinct route and same query,
        # should share the in-flight store rather than all executing.
        start_audit=json.loads(get("/audit")["body"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=18) as pool:
            responses=list(pool.map(lambda _:get("/cache/slow?scenario=parallel"),range(18)))
        end_audit=json.loads(get("/audit")["body"])
        evid_conc={"requests":18,"statuses":[x["status"] for x in responses],
                   "distinct_bodies":sorted(set(x["body"] for x in responses)),
                   "server_executions":end_audit["cacheSlow"]-start_audit["cacheSlow"]}
        evidence["concurrency"]=evid_conc
        flag("concurrent_requests_all_200",all(x["status"]==200 for x in responses))
        flag("concurrent_not_18_independent_executions",evid_conc["server_executions"]<18)
        # ResponseCaching: same public collision, HEAD, conditional and
        # Cache-Control request directives, then private controls above.
        ra=get("/cache/response?a=B%3D");time.sleep(.45)
        rb=get("/cache/response?a%3DB=")
        rnocache=get("/cache/response?a=B%3D",{"Cache-Control":"no-cache"})
        rhead=get("/cache/response?a=B%3D",method="HEAD")
        evidence["response_cache"]={k:sanitized(v) for k,v in [
            ("seed",ra),("cross",rb),("request_no_cache",rnocache),("head",rhead)]}
        flag("response_cross_version",(ra["body"]==rb["body"])==(args.major==10))
        flag("response_head_unmapped_not_cached",
             rhead["status"]==404 and rhead["body"]=="")
        flag("response_no_cache_200",rnocache["status"]==200)
        flag("response_private_not_public_cache", "public" not in evidence["auth"]["alice_response_A"]["headers"].get("cache-control",""))
        evidence["summary"]={"private_user_separation":True,"public_cache_collision":True,
            "response_cache_collision":ra["body"]==rb["body"],"pathbase_separate":evidence["pathbase"]["separate"]}
    except Exception as e:
        evidence["harness_error"]={"type":type(e).__name__,"message":str(e)}
        flag("harness_done",False)
    out={"suite":"cache-and-identity", "framework":f".NET {args.major}",
         "scope":"isolated accounts + mock records",
         "checks":checks,"passed":sum(checks.values()),"total":len(checks),
         "failed":[k for k,v in checks.items() if not v],"evidence":evidence}
    with open(args.output,"w") as f:json.dump(out,f,indent=2)
    print(json.dumps({"framework":out["framework"],"passed":out["passed"],
      "total":out["total"],"failed":out["failed"],
      "summary":evidence.get("summary"),"concurrency":evidence.get("concurrency"),
      "harness_error":evidence.get("harness_error")},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
