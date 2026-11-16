# Sixth-pass validation — 16 November 2026

Scope: controlled ASP.NET Core 10.0.15 (.NET SDK 10.0.404) and ASP.NET Core 11.0.0 (.NET SDK 11.0.100), GitHub-hosted Ubuntu runners, services bound to 127.0.0.1 / 127.0.0.2. No third-party exploitation, production credentials, personal data, or real protected resources. Written evidence, exact version logs, request/response records and executed code are retained in GitHub Actions artifacts and in the compiled ZIP delivered with this report.

**MSRC classification is provisional investigator judgment, not Microsoft assessment.** These candidates have existing public engineering changes; a reproduced parser/caching discrepancy and a valid MSRC bounty are not equivalent.

Key suites:
- [Eight-listener 32-input normalization corpus](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43867529961) — 106/106 checks each SDK.
- [Synthetic proxy-only read/write + application authorization](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43867289313) — 85/85 checks per SDK and YARP 7/7 each.
- [Authenticated cache / CSP / CORS / ETag / concurrency](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865422558) — 28/28 each.
- [Two independent Redis-backed OutputCache processes](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865422520) — 9/9 each.
- [Session, TempData, auth, antiforgery and Chromium navigation](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43864554806) — 32/32 cookie checks and 8/8 Chromium checks each.
- [Firefox and Microsoft Edge genuine browser runs](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865985773) — 8/8 on each of four jobs.

## Hypothesis and trace
MVC ResponseCaching `[ResponseCache(Duration=240,Location=Any,VaryByQueryKeys={"*"})]` serializes decoded query pairs in its cache key; the distinct pair shapes above collide on ASP.NET 10.0.15.

## Executed tests
- Exact same public responses were replayed across the two logically different query structures on .NET10; .NET11 returns its own response. Prior additional fixture confirms text/plain-vs-JSON content-type and `X-Lab-Format` substitution on .NET10 only.
- CacheControl request `no-cache`, ETag/validator and HEAD controls exercised. A HEAD to an action with only `[HttpGet]` returned 404 with empty body, correctly classified as a **negative route-control**, not a cache error.
- Authenticated MVC private responses set `Cache-Control: private`; Alice and Bob stayed distinct and unauthenticated requests returned 401. No cross-user disclosure was observed.
- Explicit named vary-key and other distinct-query controls did not show this wildcard key collision.

## Attacker capability and limits
Public response integrity only on the tested .NET10 GA runtime; no account takeover, app authorization bypass or RCE. The corresponding upstream fix [#68510](https://github.com/dotnet/aspnetcore/pull/68510) is public and observed in .NET11.

## Severity / novelty
Moderate, currently not novel to MSRC. A qualifying new result would need a *separate* Microsoft-owned cause and security-sensitive reachability, not just deeper reproductions of public response confusion.

---

## Seventh pass — actual browser CORS decision and no-store negative control

[Latest Chromium run](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915322085), 10/10 per SDK and HTTP seed checks 10/10 per SDK. The earlier MVC ResponseCaching query-key collision also changed a real browser's cross-origin `fetch` result: on ASP.NET Core **10.0.15**, the distinct B request received cached public A body and A's `Access-Control-Allow-Origin` header, allowing synthetic public A to be read by JavaScript on another origin. On **11.0.0**, B was correctly isolated and the browser rejected the response. The noncolliding B URL was blocked on both.

A separate browser fetch using `cache: "no-store"` caused B to be rejected on both versions. An earlier initial run used `no-store` for the primary test, yielding a *false negative* on .NET 10; this was corrected by testing normal browser caching and keeping `no-store` as an explicit negative control. Do not misclassify this as a sensitive cross-origin read: it returned **A's public body**, not B's private contents.

Previously public ResponseCaching fix #68510 and all private-account authorization controls remain decisive MSRC novelty/impact limitations.
