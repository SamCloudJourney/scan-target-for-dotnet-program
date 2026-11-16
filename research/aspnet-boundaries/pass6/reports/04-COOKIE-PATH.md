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
Trusted `X-Forwarded-Prefix` influences `Request.PathBase`; cookie producers may select cookie path from it. Original claim: literal delimiter escapes Path and injects a separate Domain attribute.

## Executed tests
- Five cookie producers: signed authentication cookie, Antiforgery, Session, MVC TempData and explicit normal CookieOptions; six prefix inputs (semicolon, escaped semicolon, escaped CRLF, double encoding, Unicode encoded line separator, comma), trusted and untrusted peer controls. **32/32 per SDK**.
- Real Chromium, Firefox and Edge used cookie jars and separate loopback hostname 127.0.0.2. **Every browser validated** host-only, HttpOnly and path restriction, and no cookie leakage to the other hostname.
- A trusted prefix `/;Domain=evil.example.test` was visible in `PathBase`, but the auth cookie had Path `/%3BDomain=evil.example.test`. No new cookie Domain attribute was accepted.
- Using the named ASP.NET 10/11 runtime in controlled Linux worker tests; actual domain assertion matches `evil.example.test`, not a real site.

## Observed downstream boundary
A trusted proxy can legitimately change session cookie path scope, potentially causing authentication continuity problems when backend routing disagrees. No proof of domain widening, session takeover, response splitting, or exfiltration. An earlier explicitly unsafe **developer-chosen** raw cookie path is a developer configuration control, not proof of attacker reachability through forwarded headers.

## Severity / novelty
Low or informational as a new MSRC finding; no qualifying security-attribute injection. Existing Microsoft hardening commit documented above.
