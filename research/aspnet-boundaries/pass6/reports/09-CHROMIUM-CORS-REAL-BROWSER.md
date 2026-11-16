# Seventh-pass browser CORS decision experiment — 16 Nov 2026

## Validated final run

[GitHub Actions run https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915322085](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915322085) — both `.NET SDK 10.0.404` / ASP.NET Core `10.0.15` and `SDK 11.0.100` / ASP.NET Core `11.0.0` completed successfully.

- HTTP cache seed and controls: **10/10** per version.
- Actual Chromium 157 browser-origin fetch controls: **10/10** per version.
- Complete environment: only loopback services, synthetic publicly cacheable responses and fixture origins on different HTTP ports. No production accounts or third-party requests.

## Repro steps and observations

A locally hosted HTML page loaded from `http://127.0.0.1:5207` and executed CORS-mode JavaScript `fetch` to `http://127.0.0.1:5200` in a real Chrome tab.

| Request / control | OutputCaching 10 | OutputCaching 11 | ResponseCaching 10 | ResponseCaching 11 |
|---|---|---|---|---|
| Seed A public `?a=B%3D` (decoded `a=B=`) | Cached | Cached | Cached | Cached |
| Request B `?a%3DB=` (decoded key `a=B`, empty value) | Reads cached public A | Reads cached public A | Reads cached public A on normal browser fetch | Correctly denies B due to its CORS response |
| Noncolliding B URL | Browser denied | Browser denied | Browser denied | Browser denied |
| `credentials: include` when ACA-Credentials absent | Browser denied | Browser denied | Browser denied by CORS policy | Browser denied |
| `cache: "no-store"` on colliding B | Not a tested mitigation claim for OutputCaching | Same | Browser denies B | Browser denies B |

The actual body the external-origin browser could read was **public A**, not confidential data belonging to B. The domain and credentials tests confirm a limited integrity/policy-selection defect rather than private data disclosure. No XSS, RCE, account takeover, app-level authentication bypass, or secret exfiltration was shown.

## Previous work included on same branch

[Multi-proxy normalization matrix](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43867529961) passed 106/106 per SDK.
[Real HAProxy/Nginx/YARP and synthetic authorization](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43867289313) passed 85/85 per SDK, YARP controls 7/7.
[Authenticated cache/concurrency](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865422558) passed 28/28 per SDK.
[Shared Redis cross-process cache](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865422520) passed 9/9 per SDK.
[Chrome session and redirect tests](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43864554806) plus [real Firefox/Edge](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865985773) passed.

## MSRC gate

MSRC .NET bounty eligibility requires Important or Critical security impact, and publicly known root causes are generally excluded. No finding in this series has demonstrated a *novel* Microsoft-owned Important/Critical defect. The five underlying upstream issues had public engineering discussions or fixes before these reproducible lab tests.

All experiments ran against disposable test services on a user-owned GitHub repository and recorded no real personal information.
