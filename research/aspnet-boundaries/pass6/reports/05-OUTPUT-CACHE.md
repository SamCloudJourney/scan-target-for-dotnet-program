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
Wildcard vary-by-query OutputCaching serializes distinct decoded query pairs into a colliding cache key: `?a=B%3D` (decoded name `a`, value `B=`) versus `?a%3DB=` (decoded name `a=B`, empty value). A subsequent client can receive the earlier public response.

## Executed downstream tests
- Seeded a public HTML document with Content-Type `text/html`, CSP `default-src 'self'`, CORS `http://127.0.0.1:5207`, ETag `"public-A"`, and `X-Lab-Variant: A`; the logically distinct intended JSON request received the cached A **body and response envelope** on both runtimes. `Age: 0` and a distinct query control establish actual caching.
- Alice and Bob signed cookies were used with `.RequireAuthorization()` and `.CacheOutput()` on synthetic account exports. Both received only their own identities; anonymous received 401. Set-Cookie responses were not stored. Adding Authorization header bypassed ordinary public reuse. PathBase `/tenant-a` versus `/tenant-b` generated distinct entries; explicitly named vary-key `a` separated the shapes.
- 18 simultaneous requests to a slow public endpoint produced **one** execution and one response body per runtime; concurrency did not create a new vulnerability.
- Two independent .NET processes using **real Redis** and pinned Microsoft.AspNetCore.OutputCaching.StackExchangeRedis 10.0.15/11.0.0 shared a synthetic host. Worker A's public response was returned by worker B for the collision, including `X-Lab-Instance: A`. Control: exact same request demonstrably shared; distinct key correctly returned B; cache tag eviction restored B. **9/9 per SDK**.

## Attacker capability and limits
Can seed publicly cacheable integrity-confusing response representations across visitors and across load-balanced workers when the cache namespace is shared. Wrong public CSP/CORS/ETag and HTML-versus-JSON can cause client confusion; these are **not proof of cross-origin data reading, XSS, stored script execution or private-account leakage**. No adversarial dynamic confidential values were included.

## Severity / novelty
Moderate public integrity failure; Important only if an independently shown protected boundary is crossed under supported defaults. Known and public issue #68779 and fix PR #68792 substantially undermine new MSRC bounty eligibility.

---

## Seventh pass — real cross-origin JavaScript impact

[Successful Chromium test on .NET 10 and 11](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915322085), 10/10 checks in each job, plus ten HTTP checks in each job. A page at `http://127.0.0.1:5207` executed a real `fetch` to a *different-origin* ASP.NET application at `http://127.0.0.1:5200`. At URL `?a%3DB=`, the browser received a cached **public A** HTML response seeded under `?a=B%3D`, carrying A's `Access-Control-Allow-Origin` permission. Browser CORS processing let the external-origin script read that A public body on both supported runtimes. When requesting the noncolliding B URL, the actual B `Access-Control-Allow-Origin: null` response was blocked with `TypeError`; `credentials: include` was also blocked.

**What this means:** Wrong cached response **and wrong CORS decision for the URL** are visible in a real browser, not merely a response-header diff. It does **not** mean the script read sensitive B data: the only body exposed was the *already publicly cacheable A representation*. There was no private account data and no XSS. MSRC Important remains unsubstantiated and upstream issue #68779/#68792 predates this experiment.
