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

## MSRC filing gate

The five hypotheses were investigated with multi-proxy, real-browser, private-account and distributed-cache experiments, and no new Microsoft-owned Important/Critical security boundary was established.

**Candidate ratings, subject to MSRC's own determination:** #8 Moderate/configuration-dependent (Important argument not supported by a secure default installation), #5 Moderate public integrity, #6 Moderate public integrity only on .NET10, #7 Low–Moderate unsafe rewrite, #4 Low/Informational.

Original scan labels (MEDIUM/HIGH) and number of passing test assertions do **not** imply CVSS severity or bounty. Documentation published for each root cause precedes these reproductions. Validate duplicates / timelines before filing; do not represent known issues as newly discovered zero-days.

For a new MSRC case, require:
1. Independent new root cause on a still-supported Microsoft-controlled component and exact build.
2. Reproducible **real authorization/privacy boundary crossing** not reliant on a knowingly insufficient proxy ACL, deliberately public endpoint or unsafe application rewrite.
3. Both positive exploit proof and negative controls (correct app auth, canonical request, noncolliding cache, untrusted peer, fixed build).
4. Precise roles, starting privileges, default deployment prerequisites, and security impact.
5. No production exploitation, real identity/certificate data, or public disclosure before coordinated handling.

Previous private-cookie, OAuth leakage, account compromise, RCE and application-level auth bypass hypotheses were NOT demonstrated.

Prior public root-cause material:
- Cookie security escaping: https://github.com/dotnet/aspnetcore/commit/a4866158cce1a2015e08fe0732e7f41b74423215
- OutputCaching: https://github.com/dotnet/aspnetcore/issues/68779 and https://github.com/dotnet/aspnetcore/pull/68792
- ResponseCaching: https://github.com/dotnet/aspnetcore/pull/68510
- Rewrite: https://github.com/dotnet/aspnetcore/pull/66961
- Kestrel encoded slash: https://github.com/dotnet/aspnetcore/pull/65930

MSRC .NET bounty program: https://www.microsoft.com/en-us/msrc/bounty-dot-net-core

**Submission recommendation: no new critical or important bounty submission for these five without an independently novel Microsoft-owned root cause and real qualifying customer impact.**
