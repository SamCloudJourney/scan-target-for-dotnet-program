#!/usr/bin/env python3
"""Cookie producer matrix: only forged synthetic prefix inputs on local .NET fixture."""
import argparse,http.client,json,re
H="127.0.0.1";PORT=5200
PRODUCERS=[
("/cookie/issue?user=alice","authentication"),
("/cookie/antiforgery","antiforgery"),
("/cookie/session","session"),
("/cookie/tempdata","tempdata"),
("/cookie/attributes","explicit_safe")
]
PREFIXES={
 "semicolon":"/;Domain=evil.example.test",
 "encoded_semicolon":"/%3BDomain=evil.example.test",
 "crlf":"/%0D%0ASet-Cookie:fake=1",
 "double_encoded":"/%253BDomain=evil.example.test",
 "unicode":"/x%E2%80%A8y",
 "comma":"/a,b"}
results={};checks={}
def probe(path,prefix=None,src=H):
    c=http.client.HTTPConnection(H,PORT,timeout=8,source_address=(src,0))
    c.putrequest("GET",path,skip_host=True,skip_accept_encoding=True)
    c.putheader("Host",f"{H}:{PORT}")
    if prefix is not None:c.putheader("X-Forwarded-Prefix",prefix)
    c.endheaders()
    rsp=c.getresponse()
    value=rsp.read().decode("utf-8","replace")
    cookies=[v for k,v in rsp.getheaders() if k.lower()=="set-cookie"]
    c.close()
    out=[]
    for cookie in cookies:
        attrs=cookie.split(";")
        out.append({
          "cookie_name":attrs[0].split("=",1)[0],
          "attributes":[t.strip() for t in attrs[1:]],
          "distinct_domain_attribute":bool(re.search(r";\s*domain\s*=\s*evil\.example\.test(?:;|$)",cookie,re.I)),
          "has_literal_crlf":"\r" in cookie or "\n" in cookie
        })
    return {"status":rsp.status,"body":value,"cookies":out}
def ok(name,p):checks[name]=bool(p)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",required=True)
    args=ap.parse_args()
    for label,pre in PREFIXES.items():
        for endpoint,name in PRODUCERS:
            v=probe(endpoint,pre)
            results[label+"_"+name]=v
            ok(label+"_"+name+"_no_attribute_injection",
               v["status"]==200 and
               not any(c["distinct_domain_attribute"] or c["has_literal_crlf"]
                       for c in v["cookies"]))
    # Trust boundary: X-Forwarded-Prefix from untrusted remote peer ignored.
    untrusted=probe("/cookie/issue?user=alice",PREFIXES["semicolon"],"127.0.0.2")
    results["untrusted_header"]=untrusted
    ok("untrusted_source_pathbase_ignored",untrusted["body"]=="pathbase=")
    # Sanity check that a legitimate accepted prefix is actually visible.
    trusted=probe("/cookie/issue?user=alice",PREFIXES["semicolon"])
    results["trusted_header"]=trusted
    ok("trusted_prefix_affects_pathbase","pathbase=/;Domain=evil.example.test" in trusted["body"])
    out={"suite":"cookie-producer-trust",
         "tests":len(checks),"passed":sum(checks.values()),"checks":checks,
         "failed":[k for k,v in checks.items() if not v],
         "results":results,"scope":"synthetic cookies, values withheld"}
    with open(args.output,"w") as f:json.dump(out,f,indent=2)
    print(json.dumps({"passed":out["passed"],"total":len(checks),"failed":out["failed"],
            "producer_cookie_counts":{
                p:len(results["semicolon_"+p]["cookies"])
                for _,p in PRODUCERS}},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
