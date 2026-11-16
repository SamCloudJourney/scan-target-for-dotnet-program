#!/usr/bin/env python3
"""Authorized, disposable proxy-to-Kestrel boundary experiment. All ports loopback."""
import argparse
import http.client
import json
import re
from urllib.parse import urlsplit

HOST="127.0.0.1"
PORTS={"haproxy_raw":5202,"haproxy_normalized":5203,
       "nginx_raw":5204,"nginx_normalized":5205}
BACKEND=5200
PATHS={
 "canonical":"/gate/read",
 "slash_encoded":"/gate%2Fread",
 "slash_encoded_lower":"/gate%2fread",
 "parent_literal":"/public/../gate/read",
 "parent_encoded":"/public/%2e%2e/gate/read",
 "parent_encoded_upper":"/public/%2E%2E/gate/read",
 "encoded_name":"/%67ate/read",
 "double_encoded_slash":"/gate%252Fread",
 "mixed":"/public/../gate%2Fread",
 "health":"/healthz"}
results={"proxy_matrix":{},"direct_http1":{},"state_changes":{},"authorization":{}}
checks={}
def flag(name,condition): checks[name]=bool(condition)
def req(port,target,method="GET",headers=None):
    if port not in set(PORTS.values())|{BACKEND}: raise RuntimeError("not loopback port")
    conn=http.client.HTTPConnection(HOST,port,timeout=6)
    conn.putrequest(method,target,skip_host=True,skip_accept_encoding=True)
    conn.putheader("Host",f"{HOST}:{port}")
    conn.putheader("Connection","close")
    for k,v in (headers or {}).items():conn.putheader(k,v)
    conn.endheaders()
    res=conn.getresponse()
    body=res.read().decode("utf-8","replace")
    h={k.lower():v for k,v in res.getheaders()}
    h.pop("set-cookie",None)
    conn.close()
    return {"request_target":target,"method":method,"status":res.status,
            "headers":h,"body":body}
def audit():
    return json.loads(req(BACKEND,"/audit")["body"])
def direct_auth_cookie(user):
    login=req(BACKEND,"/auth/login?user="+user)
    # Re-fetch cookie ONLY for use on in-memory requests; never persist values.
    # req() redacts Set-Cookie; this function issues its own local-only request.
    c=http.client.HTTPConnection(HOST,BACKEND,timeout=6)
    c.request("GET","/auth/login?user="+user)
    rsp=c.getresponse()
    value=rsp.getheader("Set-Cookie")
    rsp.read();c.close()
    if not value: raise RuntimeError("signed fixture cookie missing")
    return value.split(";",1)[0]
def all_proxies(method,path):
    out={}
    for label,port in PORTS.items():
        out[label]={
            "origin":req(port,path,method),
            "absolute":req(port,f"http://{HOST}:{port}{path}",method)
        }
    return out
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--major",choices=[10,11],type=int,required=True)
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    try:
        before=audit()
        for key,path in PATHS.items():
            results["proxy_matrix"][key]=all_proxies("GET",path)
            results["direct_http1"][key]={
                "origin":req(BACKEND,path),
                "absolute":req(BACKEND,f"http://{HOST}:{BACKEND}{path}") }
        for label in PORTS:
            for form in ("origin","absolute"):
                c=results["proxy_matrix"]["canonical"][label][form]
                flag("canonical_deny_"+label+"_"+form,c["status"]==403)
                health=results["proxy_matrix"]["health"][label][form]
                flag("health_accept_"+label+"_"+form,health["status"]==200)
        flag("direct_backend_read_available",results["direct_http1"]["canonical"]["origin"]["status"]==200)
        # Authentication is the independently enforced security boundary.
        cookie_a=direct_auth_cookie("alice")
        cookie_b=direct_auth_cookie("bob")
        denied={}
        for label,port in PORTS.items():
            denied[label]={}
            for form,path in [
                ("canonical","/gate/auth-read"),
                ("parent_literal","/public/../gate/auth-read"),
                ("parent_encoded","/public/%2e%2e/gate/auth-read"),
                ("encoded_slash","/gate%2Fauth-read")]:
                r=req(port,f"http://{HOST}:{port}{path}",headers=None)
                denied[label][form]=r
                flag("app_auth_read_held_"+label+"_"+form,r["status"]!=200)
            for form,path in [
                ("canonical","/gate/auth-write"),
                ("parent_literal","/public/../gate/auth-write"),
                ("parent_encoded","/public/%2e%2e/gate/auth-write")]:
                r=req(port,f"http://{HOST}:{port}{path}",method="POST")
                denied[label]["POST_"+form]=r
                flag("app_auth_write_held_"+label+"_"+form,r["status"]!=200)
        results["authorization"]["denied"] = denied
        results["authorization"]["direct_alice"] = req(BACKEND,"/gate/auth-read",headers={"Cookie":cookie_a})
        results["authorization"]["direct_bob"] = req(BACKEND,"/gate/auth-read",headers={"Cookie":cookie_b})
        flag("app_alice_allowed", "identity=alice" in results["authorization"]["direct_alice"]["body"])
        flag("app_bob_allowed", "identity=bob" in results["authorization"]["direct_bob"]["body"])
        flag("app_auth_anon_denied",req(BACKEND,"/gate/auth-read")["status"]==401)
        flag("group_auth_anon_denied",req(BACKEND,"/fallback/protected")["status"]==401)
        # Stateful consequence: model proxy-only WRITE boundary, never real data.
        cases={
            "canonical":"/gate/write",
            "parent_literal":"/public/../gate/write",
            "parent_encoded":"/public/%2e%2e/gate/write",
            "slash_encoded":"/gate%2Fwrite"}
        write_by_proxy={}
        for label,port in PORTS.items():
            write_by_proxy[label]={}
            for case,path in cases.items():
                write_by_proxy[label][case]=req(port,f"http://{HOST}:{port}{path}",method="POST")
        after=audit()
        results["state_changes"]={"before":before,"after":after,
                                  "write_by_proxy":write_by_proxy}
        successful=sum(r["status"]==200 for per in write_by_proxy.values() for r in per.values())
        flag("write_count_equals_lab_successes",
            after["restrictedWrites"]-before["restrictedWrites"]==successful)
        flag("no_auth_write_side_effects",
            after["authenticatedWrites"]-before["authenticatedWrites"]==0)
        for label,per in write_by_proxy.items():
            flag("canonical_write_denied_"+label,per["canonical"]["status"]==403)
        # HAProxy normalization regression: dot segments denied on hardened listener.
        for p in ("parent_literal","parent_encoded"):
            for form in ("origin","absolute"):
                flag("haproxy_normalized_"+p+"_"+form,
                     results["proxy_matrix"][p]["haproxy_normalized"][form]["status"]==403)
        results["summary"]={
            "synthetic_restricted_reads":[
                {"proxy":proxy,"path":p,"form":form}
                for p,values in results["proxy_matrix"].items()
                if p!="health" for proxy,forms in values.items()
                for form,row in forms.items()
                if row["status"]==200 and "SYNTHETIC-RESTRICTED-READ" in row["body"]],
            "synthetic_writes_by_proxy":{
                label:[case for case,row in per.items() if row["status"]==200]
                for label,per in write_by_proxy.items()},
            "real_protected_route_compromised":False
        }
    except Exception as exc:
        results["exception"]={"type":type(exc).__name__,"message":str(exc)}
        flag("harness_completed",False)
    data={"suite":"cross-proxy", "framework":f"ASP.NET Core {args.major}",
          "scope":"loopback synthetic only",
          "checks":checks,"passed":sum(checks.values()),"total":len(checks),
          "failed":[k for k,v in checks.items() if not v], "results":results}
    with open(args.output,"w") as f:json.dump(data,f,indent=2)
    print(json.dumps({"framework":data["framework"],"passed":data["passed"],
        "total":data["total"],"failed":data["failed"],
        "summary":results.get("summary"),
        "exception":results.get("exception")},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
