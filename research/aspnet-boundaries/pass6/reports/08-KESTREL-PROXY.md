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

## Hypothesis and root-cause separation
An ingress reverse proxy enforces a raw path-prefix policy while Kestrel/ASP.NET routes an equivalent normalized path. Absolute-form HTTP/1 encoded slash `%2F` was parsed differently on .NET10 than on .NET11 (previous Microsoft PR #65930). Dot-segment normalization is a separate cross-version URI normalization behaviour, and route casing can differ from proxy ACL defaults.

## Executed tests
- **Real HAProxy and Nginx**, both raw-path and URI-normalizing policies; **Microsoft YARP** 2.3.0 with ASP.NET case-insensitive `StartsWithSegments`; HTTP/1 origin-form and absolute-form and Kestrel HTTP/2 h2c.
- Proxy-only restrictions protected *synthetic* endpoints `/gate/read` and `POST /gate/write`. Raw HAProxy path policy allowed the synthetic backend write **three** times on .NET10 (literal parent, encoded parent and absolute-form encoded slash) and **twice** on .NET11 (two parent variants). Back-end test counter matched the successful HTTP200 responses. This proves side effect in a deliberately weak **proxy-only** authorization model.
- For **app-level** `/gate/auth-read` and `/gate/auth-write` with `.RequireAuthorization()`, unauthorized requests were denied. Authenticated write counter remained **zero**; Alice/Bob signed sessions successfully accessed the app-protected read only with valid cookie.
- HTTP/2 encoded-slash path remained unrouted (404), dot segments were normalized and routed (200) on both versions when directly accessing public fixture, and app-auth endpoint returned 401.
- Final 32-input corpus across 7 proxy/listener policies (8 including direct Kestrel) and two request-target forms: 106/106 assertions each SDK. Raw HAProxy had 32 net10 / 28 net11 proxy-only misses, raw Nginx 28/28, HAProxy/Nginx normalized but **case-sensitive** 2/2 each, YARP 0/0, HAProxy/Nginx normalized **case-insensitive** 0/0.
- The case-sensitive normalized policies' two misses stemmed from mixed-case route selection; the hardened local listeners aligning proxy normalization and case-insensitive prefix rules blocked the fixed corpus. **Not a universal security proof** for arbitrary URI encodings.

## Corrected false-positive warning
An early corpus auth check accidentally targeted a public URL when an encoded slash prevented a literal replacement from matching. The suite was corrected and re-run with asserted authentic protected-route target. **There are zero verified ASP.NET authentication bypasses**. Do not attribute any old false-positive HTTP200 to `.RequireAuthorization()`.

## Attacker capability and limits
An attacker can access or change an *application fixture* resource when its security relies solely on insufficient raw reverse-proxy path ACL, and the backend normalizes/routs the request differently. The observed read/write capability is contingent on **developer/proxy policy design**, not proof of a Microsoft-owned authentication-bypass vulnerability. The earlier .NET10 absolute-form encoded-slash issue is public; the cross-version dot-segment/case mismatch is not established as a new .NET security defect.

## Severity / novelty
Most serious synthetic impact among the five, but likely Moderate/configuration-dependent for MSRC under present proof. Important would require direct, realistic Microsoft-owned boundary crossing with independent protected data and a novel cause; current tests favor application/proxy configuration issues. Critical/RCE/ATO unsupported.
