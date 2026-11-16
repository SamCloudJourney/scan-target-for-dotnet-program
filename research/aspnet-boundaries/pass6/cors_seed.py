#!/usr/bin/env python3
"""Compare wrong public OutputCache CORS policy to an unpoisoned control."""
import http.client,json,sys
def req(path):
 c=http.client.HTTPConnection("127.0.0.1",5200,timeout=7);c.request("GET",path)
 r=c.getresponse();h={k.lower():v for k,v in r.getheaders()};b=r.read().decode();c.close()
 return {"status":r.status,"body":b,"acao":h.get("access-control-allow-origin"),"content_type":h.get("content-type"),"etag":h.get("etag"),"age":h.get("age")}
a=req("/cache/public?a=B%3D")
b=req("/cache/public?a%3DB=")
ctl=req("/cache/public?a%3DB=&uniquecontrol=yes")
checks={
 "public_A_html":a["status"]==200 and "text/html" in (a["content_type"] or ""),
 "public_colliding_B_receives_A":b["status"]==200 and b["body"]==a["body"],
 "public_colliding_B_receives_A_ACAO":b["acao"]=="http://127.0.0.1:5207",
 "public_B_control_json":ctl["status"]==200 and "application/json" in (ctl["content_type"] or ""),
 "public_B_control_no_ACAO_for_origin":ctl["acao"]=="null"}
out={"checks":checks,"passed":sum(checks.values()),"total":len(checks),"samples":{"A":a,"B_collision":b,"B_control":ctl}}
with open(sys.argv[1],"w") as f:json.dump(out,f,indent=2)
print(json.dumps({"passed":out["passed"],"total":out["total"],"checks":checks,"samples":out["samples"]},indent=2))
sys.exit(0 if all(checks.values()) else 1)
