#!/usr/bin/env python3
"""Compare wrong public OutputCache CORS policy to an unpoisoned control."""
import http.client,json,sys,time
def req(path):
 c=http.client.HTTPConnection("127.0.0.1",5200,timeout=7);c.request("GET",path)
 r=c.getresponse();h={k.lower():v for k,v in r.getheaders()};b=r.read().decode();c.close()
 return {"status":r.status,"body":b,"acao":h.get("access-control-allow-origin"),"content_type":h.get("content-type"),"etag":h.get("etag"),"age":h.get("age")}
a=req("/cache/public?a=B%3D")
b=req("/cache/public?a%3DB=")
ctl=req("/cache/public?a%3DB=&uniquecontrol=yes")
respA=req("/cache/response-cors?a=B%3D")
time.sleep(.5)
respARepeat=req("/cache/response-cors?a=B%3D")
respB=req("/cache/response-cors?a%3DB=")
respCtrl=req("/cache/response-cors?a%3DB=&uniquecontrol=yes")
major=int(sys.argv[2])
checks={
 "public_A_html":a["status"]==200 and "text/html" in (a["content_type"] or ""),
 "public_colliding_B_receives_A":b["status"]==200 and b["body"]==a["body"],
 "public_colliding_B_receives_A_ACAO":b["acao"]=="http://127.0.0.1:5207",
 "public_B_control_json":ctl["status"]==200 and "application/json" in (ctl["content_type"] or ""),
 "public_B_control_no_ACAO_for_origin":ctl["acao"]=="null",
 "response_A_public":respA["status"]==200 and "variant=A" in respA["body"],
 "response_A_repeated_cached":respARepeat["body"]==respA["body"],
 "response_B_collision_version":(respB["body"]==respA["body"])==(major==10),
 "response_B_ACAO_version":(respB["acao"]=="http://127.0.0.1:5207")==(major==10),
 "response_B_unpoisoned_control":respCtrl["status"]==200 and "variant=B" in respCtrl["body"] and respCtrl["acao"]=="null"}
out={"checks":checks,"passed":sum(checks.values()),"total":len(checks),"samples":{"A":a,"B_collision":b,"B_control":ctl,"response_A":respA,"response_A_repeat":respARepeat,"response_B_collision":respB,"response_B_control":respCtrl}}
with open(sys.argv[1],"w") as f:json.dump(out,f,indent=2)
print(json.dumps({"passed":out["passed"],"total":out["total"],"checks":checks,"samples":out["samples"]},indent=2))
sys.exit(0 if all(checks.values()) else 1)
