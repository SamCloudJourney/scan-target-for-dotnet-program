#!/usr/bin/env python3
"""YARP-only safe cross-proxy controls, all synthetic requests remain loopback."""
import json,http.client,sys
host="127.0.0.1"
samples={}
checks={}
def probe(target,method="GET"):
    c=http.client.HTTPConnection(host,5206,timeout=8)
    c.putrequest(method,target,skip_host=True,skip_accept_encoding=True)
    c.putheader("Host","127.0.0.1:5206")
    c.endheaders()
    r=c.getresponse()
    data={"target":target,"method":method,"status":r.status,"body":r.read().decode("utf-8","replace")}
    c.close()
    return data
for label,path in [
    ("health","/healthz"),
    ("canonical","/gate/read"),
    ("encoded_slash","/gate%2Fread"),
    ("parent","/public/../gate/read"),
    ("encoded_parent","/public/%2e%2e/gate/read"),
    ("auth_parent","/public/../gate/auth-read")
]:
    for form,target in (("origin",path),("absolute",f"http://{host}:5206{path}")):
        samples[label+"_"+form]=probe(target)
for form in ("origin","absolute"):
    checks["health_"+form]=samples["health_"+form]["status"]==200
    checks["canonical_denied_"+form]=samples["canonical_"+form]["status"]==403
    checks["app_auth_denied_"+form]=samples["auth_parent_"+form]["status"]!=200
checks["no_synthetic_write_tested"]=True
out={"suite":"yarp","samples":samples,"checks":checks,
     "passed":sum(checks.values()),"total":len(checks),
     "failed":[k for k,v in checks.items() if not v]}
with open(sys.argv[1],"w") as f:json.dump(out,f,indent=2)
print(json.dumps({"passed":out["passed"],"total":out["total"],"failed":out["failed"],
"statuses":{k:v["status"] for k,v in samples.items()}},indent=2))
sys.exit(0 if all(checks.values()) else 1)
