#!/usr/bin/env python3
"""Two independent localhost ASP.NET workers sharing ONLY synthetic Redis responses."""
import argparse,http.client,json,time,concurrent.futures
HOST="127.0.0.1";PORTS={"A":5210,"B":5211}
rows={}; checks={}
def get(instance,path,headers=None):
    c=http.client.HTTPConnection(HOST,PORTS[instance],timeout=8)
    c.putrequest("GET",path,skip_host=True,skip_accept_encoding=True)
    c.putheader("Host",f"{HOST}:{PORTS[instance]}")
    for k,v in (headers or {}).items(): c.putheader(k,v)
    c.endheaders()
    r=c.getresponse()
    body=r.read().decode("utf-8","replace")
    data={"status":r.status,"body":body,
          "headers":{k.lower():v for k,v in r.getheaders()}}
    c.close();return data
def flag(k,v):checks[k]=bool(v)
def main():
    p=argparse.ArgumentParser();p.add_argument("--major",type=int,choices=(10,11),required=True)
    p.add_argument("--output",required=True);args=p.parse_args()
    try:
        rows["A_seed"]=get("A","/redis/public?a=B%3D")
        time.sleep(0.35)
        rows["B_collision"]=get("B","/redis/public?a%3DB=")
        rows["B_noncrossing"]=get("B","/redis/public?a%3DB=&isolation=1")
        rows["B_client_nocache"]=get("B","/redis/public?a%3DB=",{"Cache-Control":"no-cache"})
        flag("A_seed_correct",rows["A_seed"]["status"]==200 and "instance=A;variant=A" in rows["A_seed"]["body"])
        flag("B_cross_instance_collision",rows["B_collision"]["body"]==rows["A_seed"]["body"])
        flag("B_cross_instance_header",rows["B_collision"]["headers"].get("x-lab-instance")=="A")
        flag("B_control_isolated",rows["B_noncrossing"]["status"]==200 and "instance=B;variant=B" in rows["B_noncrossing"]["body"])
        flag("B_nocache_server_policy_still_cache",rows["B_client_nocache"]["body"]==rows["A_seed"]["body"])
        rows["invalidate"]=get("B","/redis/evict")
        time.sleep(0.3)
        rows["B_after_evict"]=get("B","/redis/public?a%3DB=")
        flag("tag_eviction_success",rows["invalidate"]["status"]==200 and
             "tag-invalidation-done" in rows["invalidate"]["body"])
        flag("B_after_evict_correct", "instance=B;variant=B" in rows["B_after_evict"]["body"])
        # Concurrency after eviction on DIFFERENT new key shapes; observe
        # which server writes. It is evidence, not an assumed vulnerability.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            concurrent=list(pool.map(lambda idx:get("A" if idx%2 else "B",
                "/redis/public?a=B%3D&scenario=parallel" if idx%2 else
                "/redis/public?a%3DB=&scenario=parallel"),range(8)))
        rows["parallel"]={
            "statuses":[x["status"] for x in concurrent],
            "content_pairs":sorted(set(x["body"] for x in concurrent))}
        flag("parallel_all_success",all(x["status"]==200 for x in concurrent))
    except Exception as e:
        rows["error"]={"kind":type(e).__name__,"detail":str(e)}
        flag("harness_error",False)
    out={"suite":"redis-multi-instance-outputcache",
         "framework":f"ASP.NET Core {args.major}",
         "checks":checks,"passed":sum(checks.values()),
         "total":len(checks),"failed":[k for k,v in checks.items() if not v],
         "observations":rows}
    with open(args.output,"w") as f:json.dump(out,f,indent=2)
    print(json.dumps({"framework":out["framework"],"passed":out["passed"],
       "total":out["total"],"failed":out["failed"],
       "seed":rows.get("A_seed",{}).get("body"),
       "cross_instance":rows.get("B_collision",{}).get("body"),
       "after_evict":rows.get("B_after_evict",{}).get("body"),
       "error":rows.get("error")},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
