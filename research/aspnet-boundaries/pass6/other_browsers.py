#!/usr/bin/env python3
"""Firefox / Edge cookie and redirect observations on two independent loopback IPs."""
import argparse,json,sys
from playwright.sync_api import sync_playwright
p=argparse.ArgumentParser()
p.add_argument("--browser",required=True,choices=["firefox","msedge"])
p.add_argument("--major",required=True,type=int,choices=[10,11])
p.add_argument("--output",required=True)
args=p.parse_args()
APP="http://127.0.0.1:5200";RECEIVER="http://127.0.0.2:5207"
checks={};results={"browser":args.browser,"major":args.major}
def flag(key,value):checks[key]=bool(value)
try:
    with sync_playwright() as pw:
        browser = pw.firefox.launch(headless=True) if args.browser=="firefox" else (
            pw.chromium.launch(channel="msedge", headless=True,
                               args=["--no-sandbox","--no-proxy-server"]))
        try:
            ctx=browser.new_context(extra_http_headers={
                "X-Forwarded-Prefix":"/;Domain=evil.example.test"},ignore_https_errors=False)
            page=ctx.new_page()
            page.goto(APP+"/cookie/issue?user=alice",wait_until="load",timeout=20000)
            all_cookies=ctx.cookies()
            matching=[c for c in all_cookies if c["name"]=="pass6.auth"]
            results["stored_cookie_metadata"]=[
                {k:v for k,v in c.items() if k not in ("value",)}
                for c in matching]
            flag("cookie_stored",len(matching)==1)
            flag("no_attacker_domain",len(matching)==1 and
                 matching[0]["domain"].strip(".")=="127.0.0.1")
            flag("httponly",len(matching)==1 and matching[0]["httpOnly"])
            flag("not_sent_to_root",not any(c["name"]=="pass6.auth" for c in ctx.cookies([APP+"/auth/export"])))
            flag("sent_to_encoded_path",any(c["name"]=="pass6.auth" for c in
                 ctx.cookies([APP+"/%3BDomain=evil.example.test/auth/export"])))
            flag("not_sent_to_other_host",not any(c["name"]=="pass6.auth" for c in
                 ctx.cookies([RECEIVER+"/receiver"])))
            ctx.set_extra_http_headers({})
            page.goto(APP+"/auth/login?user=bob",wait_until="load",timeout=20000)
            # Browser follows a real redirect; only a PUBLIC marker is present.
            page.goto(APP+"/legacy//127.0.0.2:5207/receiver?marker=PUBLIC-BROWSER",
                      wait_until="load",timeout=25000)
            results["unsafe_redirect_final_url"]=page.url
            flag("unsafe_redirect_final_origin_version",
                 page.url.startswith(RECEIVER+"/receiver")==(args.major==10))
            page.goto(APP+"/safe//127.0.0.2:5207/receiver?marker=SAFE",
                      wait_until="load",timeout=25000)
            results["safe_redirect_final_url"]=page.url
            flag("safe_redirect_kept_local",page.url.startswith(APP+"/"))
            ctx.close()
        finally:browser.close()
except Exception as exc:
    results["exception"]={"type":type(exc).__name__,"text":str(exc)[:1200]}
    flag("browser_harness_completed",False)
results["checks"]=checks
results["passed"]=sum(checks.values())
results["total"]=len(checks)
results["failed"]=[k for k,v in checks.items() if not v]
with open(args.output,"w") as f:json.dump(results,f,indent=2)
print(json.dumps({k:v for k,v in results.items()
                  if k!="stored_cookie_metadata"},indent=2))
sys.exit(0 if all(checks.values()) else 1)
