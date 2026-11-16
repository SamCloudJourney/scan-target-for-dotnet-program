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
With an app-authored unsafe capture-first `RewriteOptions.AddRedirect(@"^legacy/(.*)$", "/$1",302)`, a URL containing `/legacy//127.0.0.2:5207/receiver?marker=PUBLIC-BROWSER` makes .NET10 emit a scheme-relative Location and browser navigates to a second loopback hostname.

## Executed tests
- Real Chrome/Chromium, Edge and Firefox browsers (not just HTTP clients) followed the .NET10 redirect to loopback `127.0.0.2:5207`; .NET11 kept navigation on original `127.0.0.1:5200`.
- A fixed-prefix rule `/local/$1` stayed local on both versions.
- The receiver observed only a **benign, attacker-supplied PUBLIC marker**, no cookie or confidential token; host-only auth cookie did not travel with the cross-origin redirect. Browser test used distinct IP loopback hosts to make host-boundary checks meaningful.

## Attacker capability and limits
Can cause off-origin navigation (phishing pretext) when the victim application installs this unsafe rewrite. A user's *own* URL query follows the redirect, but no confidential **application-generated** values or OAuth tokens were shown to leak. No authorization failure or account takeover.

## Severity / novelty
Low–Moderate, explicit unsafe app rule required. The root cause is already addressed in public PR #66961 and differs between .NET10 (affected) and .NET11 (corrected).
