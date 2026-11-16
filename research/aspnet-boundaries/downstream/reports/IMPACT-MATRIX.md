# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## Ranking by observed effect, not scan severity

| Rank | Finding ID | Demonstrated downstream behaviour | Versions | Critical limitation |
|---:|---|---|---|---|
| 1 | #8 `csf_5f0b0ee071706c52ce7d4fdc` | A proxy-only protected synthetic document is returned despite a HAProxy deny rule | .NET 10 | Requires HTTP/1 absolute-form and an unsafe upstream path ACL; application authentication still returns 401 |
| 2 | #7 `csf_b734f672ce60b9405fb74320` | 302 Location leads an actual HTTP client to a second loopback origin | .NET 10 | Requires unsafe app rewrite rule; no real phishing or secret transfer |
| 3 | #5 `csf_c161401c3d8d2d485458f8b8` | Public response body and X-Lab-Variant header seeded by one client replayed to a distinct query shape | .NET 10 and 11 | Public response only; authenticated private body did not leak |
| 4 | #6 `csf_f26364d11e0ae0c1bab0aef5` | Same incorrect public body/header reuse as #5 | .NET 10 | Fixed behaviour in .NET 11; no cross-user private data |
| 5 | #4 `csf_dba0cb9af03ecbc0c80b42bf` | No injected cookie attribute in tested request-derived auth, antiforgery or TempData cookies | Neither | Explicit, unsafe app-configured CookieOptions.Path is separable from attacker-controlled PathBase |

## Attacker influence boundaries

**Attacker-controlled:** decoded query names/values, one requested redirect path capture, absolute-form HTTP request-target bytes, and a forwarded prefix **only when** a trusted proxy permits or originates the header. Tests seed all traffic locally.

**Not attacker-controlled in the proof:** ASP.NET application source, private cookie signing keys, protected-route policy, authentication sessions, HAProxy rules, upstream Microsoft versions, and private records. Where a route is proxy-only protected, that is an explicit experimental application configuration.

### Hardening experiment

The same HAProxy fixture has two listeners:
- 5102: `acl sensitive_path path_beg /gate/` (vulnerable-by-design relative to the downstream decoder).
- 5104: `acl sensitive_path path,url_dec -m beg /gate/` (decoding before that ACL's path-prefix decision).

A .NET 10 absolute-form encoded slash reached the synthetic document via port 5102 (HTTP 200), but was refused through port 5104 (HTTP 403). This single-step normalization mitigates the tested form only; it is **not** proof of a complete bypass-resistant HAProxy authorization policy for arbitrary encodings or chains.

## MSRC readiness

**Do not submit these five as independent zero-days on this evidence.** Existing upstream work already describes the core root causes: [cookie hardening](https://github.com/dotnet/aspnetcore/commit/a4866158cce1a2015e08fe0732e7f41b74423215), [OutputCaching issue #68779](https://github.com/dotnet/aspnetcore/issues/68779), [ResponseCaching PR #68510](https://github.com/dotnet/aspnetcore/pull/68510), [Rewrite PR #66961](https://github.com/dotnet/aspnetcore/pull/66961) and [Kestrel PR #65930](https://github.com/dotnet/aspnetcore/pull/65930). A qualifying new root cause or demonstrably new impact would need independent evidence. None was found in this pass.

This file ranks strictly by **observed local impact**. It does not assign CVSS or predict bounty awards.
