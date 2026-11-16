#!/usr/bin/env python3
"""Fourth-pass loopback-only tests: HTTP validators, named vary controls, and proxy URI normalization."""
import argparse, http.client, json, time

HOST="127.0.0.1"
APP=5100
PORTS={"raw":5112, "normalized":5114, "normalized_decoded":5116}
samples={}
checks={}
def get(path, port=APP, headers=None):
    if port not in (APP,*PORTS.values()): raise RuntimeError("refusing non-loopback port")
    c=http.client.HTTPConnection(HOST,port,timeout=8)
    c.putrequest("GET",path,skip_host=True,skip_accept_encoding=True)
    c.putheader("Host",f"{HOST}:{port}")
    c.putheader("Connection","close")
    for k,v in (headers or {}).items():c.putheader(k,v)
    c.endheaders()
    res=c.getresponse()
    row={"path":path,"port":port,"status":res.status,"headers":dict((k.lower(),v) for k,v in res.getheaders()),"body":res.read().decode("utf-8","replace")}
    c.close()
    return row
def ok(name,yes):checks[name]=bool(yes)
def identity_cookie(name):
    res=get("/cookie/issue?user="+name)
    if res["status"]!=200:raise RuntimeError("fixture sign-in failed")
    return res["headers"]["set-cookie"].split(";",1)[0]

def cache_case(name, expected_collision, json_output):
    prefix="/fourth/"+name+"/etag"
    A=prefix+"?a=B%3D"
    B=prefix+"?a%3DB="
    first=get(A);time.sleep(.50)
    same=get(A);time.sleep(.35)
    crossed=get(B);time.sleep(.15)
    a_tag=first["headers"].get("etag","")
    conditional=get(B,headers={"If-None-Match":a_tag});time.sleep(.15)
    differing_tag=get(B,headers={"If-None-Match":'"unrelated-synthetic-validator"'})
    results={
        "seed_A":first,"repeat_A":same,"cross_query_B":crossed,
        "if_none_match_A_on_B":conditional,"if_none_match_wrong_tag_on_B":differing_tag
    }
    samples["cache_"+name]=results
    ok(name+"_seed_ok",first["status"]==200 and bool(a_tag))
    ok(name+"_same_query_reused",same["body"]==first["body"])
    ok(name+"_B_validator_collides_as_expected",
       (crossed["headers"].get("etag")==a_tag)==expected_collision)
    ok(name+"_B_body_collides_as_expected",
       (crossed["body"]==first["body"])==expected_collision)
    ok(name+"_B_conditional_304_as_expected",
       (conditional["status"]==304)==expected_collision)
    ok(name+"_B_different_validator_returns_body",differing_tag["status"]==200)
    return results

def named_case(name):
    prefix="/fourth/"+name+"/fixed"
    A=prefix+"?a=B%3D"
    B=prefix+"?a%3DB="
    first=get(A);time.sleep(.5)
    repeat=get(A);time.sleep(.2)
    second=get(B)
    samples["named_"+name]={"seed_A":first,"repeat_A":repeat,"distinct_B":second}
    ok(name+"_named_key_same_request_cache",first["body"]==repeat["body"])
    ok(name+"_named_key_distinct_pair_isolated",
       "fixed-"+name+"=B" in second["body"] and second["body"]!=first["body"])

def client_contract():
    root="/fourth/output/client-json"
    seed=get(root+"?a=B%3D");time.sleep(.35)
    poisoned=get(root+"?a%3DB=")
    control=get(root+"?a%3DB=valid&independent=1")
    def parse(data):
        try:return {"json_ok":True,"value":json.loads(data["body"])}
        except (ValueError,TypeError) as e:return {"json_ok":False,"exception_type":type(e).__name__}
    parsed_poisoned=parse(poisoned)
    parsed_control=parse(control)
    samples["json_client_contract"]={
        "attacker_public_html_seed":seed,
        "client_intended_json":poisoned,
        "client_noncolliding_json_control":control,
        "parsed_poisoned":parsed_poisoned,
        "parsed_control":parsed_control,
    }
    ok("output_wrong_html_given_to_json_client",
       "text/html" in poisoned["headers"].get("content-type",""))
    ok("output_json_parser_fails_on_collision",
       not parsed_poisoned["json_ok"] and "Syntax" not in parsed_poisoned.get("exception_type",""))
    ok("output_json_parser_works_on_control",
       parsed_control["json_ok"] and parsed_control["value"].get("variant")=="B")
    ok("output_wrong_content_type_delivered",poisoned["headers"].get("x-lab-representation")=="html")

def authenticated_case():
    alice,bob=identity_cookie("alice"),identity_cookie("bob")
    path="/fourth/auth/query"
    A=get(path+"?a=B%3D",headers={"Cookie":alice})
    B=get(path+"?a%3DB=",headers={"Cookie":bob})
    anon=get(path+"?a=B%3D")
    samples["authenticated_control"]={"alice":A,"bob":B,"anonymous":anon}
    ok("no_cross_account_output_access",A["status"]==200 and B["status"]==200
       and "private-identity=alice" in A["body"] and "private-identity=bob" in B["body"])
    ok("anonymous_still_unauthorized",anon["status"]==401)

def proxy_matrix(major):
    paths={
        "canonical":"/gate/private-document",
        "parent":"/public/../gate/private-document",
        "encoded_parent":"/public/%2e%2e/gate/private-document",
        "encoded_g":"/%67ate/private-document",
        "encoded_slash":"/gate%2Fprivate-document",
        "encoded_both":"/%67ate%2Fprivate-document",
        "mixed":"/public/%2e%2e/gate%2Fprivate-document",
        "double_encoded_slash":"/gate%252Fprivate-document",
        "healthy":"/healthz",
    }
    matrices={}
    for tag,path in paths.items():
        matrices[tag]={}
        for label,port in PORTS.items():
            absolute=f"http://{HOST}:{port}{path}"
            matrices[tag][label]=get(absolute,port)
    samples["proxy_normalizer_matrix"]=matrices
    for label in PORTS:
        ok(label+"_canonical_deny",matrices["canonical"][label]["status"]==403)
        ok(label+"_health_works",matrices["healthy"][label]["status"]==200)
    for tag in ("parent","encoded_parent"):
        ok(tag+"_raw_mismatch",matrices[tag]["raw"]["status"]==200)
        ok(tag+"_normalized_deny",matrices[tag]["normalized"]["status"]==403)
        ok(tag+"_normalized_decoded_deny",matrices[tag]["normalized_decoded"]["status"]==403)
    ok("encoded_slash_raw_version", (matrices["encoded_slash"]["raw"]["status"]==200)==(major==10))
    ok("encoded_slash_normalized_decoded_denied",matrices["encoded_slash"]["normalized_decoded"]["status"]==403)
    ok("encoded_both_normalized_decoded_denied",matrices["encoded_both"]["normalized_decoded"]["status"]==403)
    # Observed 200 values are recorded, never automatically interpreted as a new CVE.
    samples["proxy_200_summary"]={
        label:[tag for tag,rows in matrices.items()
               if tag!="healthy" and rows[label]["status"]==200]
        for label in PORTS
    }
    # Application authorization remains the independent boundary
    auth="/public/../gate/auth-private-document"
    authorized_probes={}
    for label,port in PORTS.items():
        authorized_probes[label]=get(f"http://{HOST}:{port}{auth}",port)
    samples["auth_proxy_checks"]=authorized_probes
    ok("proxy_authorization_boundary_intact",
       all(row["status"]!=200 for row in authorized_probes.values()))

def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--major",type=int,choices=(10,11),required=True)
    cli.add_argument("--output",required=True)
    args=cli.parse_args()
    try:
        cache_case("output",True,True)
        cache_case("response",args.major==10,False)
        named_case("output")
        named_case("response")
        client_contract()
        authenticated_case()
        proxy_matrix(args.major)
    except Exception as e:
        samples["exception"]={"type":type(e).__name__,"message":str(e)}
        ok("harness_executed_without_exception",False)
    report={
       "framework":f"ASP.NET Core {args.major}.0",
       "scope":"isolated loopback GitHub Actions runner; no third-party data",
       "passed":sum(checks.values()),"total":len(checks),
       "failed_checks":[k for k,v in checks.items() if not v],
       "checks":checks,"requests":samples
    }
    with open(args.output,"w") as out:json.dump(report,out,indent=2)
    focus={
       "framework":report["framework"],
       "passed":report["passed"],"total":report["total"],
       "failed_checks":report["failed_checks"],
       "etag":{
         name:{
           "A_etag":case["seed_A"]["headers"].get("etag"),
           "B_etag":case["cross_query_B"]["headers"].get("etag"),
           "B_if_none_match_A_status":case["if_none_match_A_on_B"]["status"],
           "B_status":case["cross_query_B"]["status"],
         } for name,case in [
           ("output",samples.get("cache_output",{})),
           ("response",samples.get("cache_response",{}))]
         if case and "seed_A" in case},
       "json_contract":{
           "poisoned":samples.get("json_client_contract",{}).get("parsed_poisoned"),
           "control":samples.get("json_client_contract",{}).get("parsed_control")},
       "proxy_200_summary":samples.get("proxy_200_summary")
    }
    print(json.dumps(focus,indent=2))
    return 0 if all(checks.values()) else 1
if __name__=="__main__":
    raise SystemExit(main())
