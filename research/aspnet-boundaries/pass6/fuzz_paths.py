#!/usr/bin/env python3
"""Deterministic local differential path-normalization corpus; no production target."""
import argparse,http.client,json
HOST="127.0.0.1"
PORTS={"backend":5200,"haproxy_raw":5202,"haproxy_normalized":5203,
       "nginx_raw":5204,"nginx_normalized":5205,"yarp":5206}
CORPUS={
"canonical":"/gate/read",
"uppercase_route":"/GaTe/read",
"encoded_separator_upper":"/gate%2Fread",
"encoded_separator_lower":"/gate%2fread",
"double_encoded_slash":"/gate%252Fread",
"encoded_first_letter":"/%67ate/read",
"encoded_last_letter":"/ga%74e/read",
"parent_literal":"/public/../gate/read",
"parent_encoded":"/public/%2e%2e/gate/read",
"parent_mixed1":"/public/%2E./gate/read",
"parent_mixed2":"/public/.%2e/gate/read",
"parent_double_encoded":"/public/%252e%252e/gate/read",
"parent_extra_slash":"/public//../gate/read",
"parent_trailing_slash":"/public/..//gate/read",
"parent_then_encoded_name":"/public/../%67ate/read",
"parent_then_encoded_slash":"/public/../gate%2Fread",
"encoded_parent_then_encoded_slash":"/public/%2e%2e/gate%2Fread",
"parent_then_dot":"/public/.././gate/read",
"parent_then_encoded_dot":"/public/../%2e/gate/read",
"encoded_parent_upper":"/public/%2E%2E/gate/read",
"nested_parent":"/other/parent/../../gate/read",
"nested_parent_encoded":"/other/parent/%2E%2E/%2e%2e/gate/read",
"query_marked":"/gate/read?marker=PUBLIC",
"query_parent":"/public/../gate/read?marker=PUBLIC",
"backslash_separator":"/gate%5cread",
"backslash_parent":"/public/..%5cgate/read",
"semicolon_segment":"/gate;/read",
"dot_within_target":"/gate/./read",
"encoded_dot_within_target":"/gate/%2e/read",
"leading_double_slash":"//gate/read",
"safe":" /healthz".strip(),
"innocent_prefix":"/gatehouse/read",
}
data={};checks={}
def flag(k,v):checks[k]=bool(v)
def query(port,path):
    c=http.client.HTTPConnection(HOST,port,timeout=7)
    try:
        c.putrequest("GET",path,skip_host=True,skip_accept_encoding=True)
        c.putheader("Host",f"{HOST}:{port}")
        c.putheader("Connection","close");c.endheaders()
        response=c.getresponse()
        text=response.read().decode("utf-8","replace")
        return {"status":response.status,"body":text[:280],
                "path":path,"response_type":response.getheader("Content-Type")}
    except (ConnectionError,OSError,http.client.HTTPException) as e:
        return {"exception":type(e).__name__,"message":str(e)[:180],"path":path}
    finally:c.close()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--major",type=int,choices=(10,11),required=True)
    ap.add_argument("--output",required=True)
    a=ap.parse_args()
    for label,path in CORPUS.items():
        data[label]={}
        for proxy,port in PORTS.items():
            data[label][proxy]={}
            for form,target in [
                ("origin",path),
                ("absolute",f"http://{HOST}:{port}{path}")]:
                data[label][proxy][form]=query(port,target)
    # Never treat a proxy-only 200 as an application-authenticated bypass.
    auth_vectors={}
    for label in ("canonical","encoded_separator_upper","parent_literal","parent_encoded",
                  "parent_mixed1","parent_mixed2","nested_parent",
                  "parent_then_encoded_slash"):
        path=CORPUS[label].replace("/gate/read","/gate/auth-read")
        auth_vectors[label]={}
        for proxy,port in PORTS.items():
            auth_vectors[label][proxy]=query(port,f"http://{HOST}:{port}{path}")
            flag("app_auth_"+label+"_"+proxy,
                 auth_vectors[label][proxy].get("status")!=200)
    for proxy in PORTS:
        for form in ("origin","absolute"):
            flag("canonical_"+proxy+"_"+form,
                 data["canonical"][proxy][form].get("status")==
                 (200 if proxy=="backend" else 403))
            flag("healthy_"+proxy+"_"+form,
                 data["safe"][proxy][form].get("status")==200)
    bypasses={p:[] for p in PORTS if p!="backend"}
    for label in CORPUS:
        if label in ("safe","canonical","innocent_prefix"):continue
        for proxy in bypasses:
            for form in ("origin","absolute"):
                v=data[label][proxy][form]
                if v.get("status")==200 and "SYNTHETIC-RESTRICTED-READ" in v.get("body",""):
                    bypasses[proxy].append({"case":label,"form":form})
    results={"suite":"proxy-path-corpus","framework":f".NET {a.major}",
        "requested_cases":len(CORPUS),"proxies":list(PORTS),
        "path_matrix":data,"auth_matrix":auth_vectors,
        "proxy_only_policy_misses":bypasses,
        "application_authentication_bypasses":[
            {"case":case,"proxy":proxy}
            for case,groups in auth_vectors.items()
            for proxy,v in groups.items() if v.get("status")==200],
        "checks":checks,"passed":sum(checks.values()),"total":len(checks),
        "failed":[k for k,v in checks.items() if not v]}
    with open(a.output,"w") as f:json.dump(results,f,indent=2)
    print(json.dumps({"framework":results["framework"],"passed":results["passed"],
     "total":results["total"],"failed":results["failed"],
     "proxy_miss_counts":{k:len(v) for k,v in bypasses.items()},
     "auth_bypasses":results["application_authentication_bypasses"]},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
