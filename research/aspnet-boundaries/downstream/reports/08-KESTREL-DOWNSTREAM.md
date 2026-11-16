# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## #8: HAProxy-to-Kestrel upstream path-rule bypass and mitigating policy

**Source → sink:** HTTP/1 absolute-form target with `%2F` → HAProxy raw-path `path_beg` deny rule → forwarded request → Kestrel 10's `Uri.LocalPath` conversion → route matched as `/gate/private-document`. ASP.NET Core 11 preserves `%2F` and does not match that route.

**New real-proxy experiment:** two HAProxy listeners on loopback under the **same version** and backend:
- Raw `path_beg /gate/` on port 5102 denied canonical `/gate/private-document` (403). The absolute-form encoded target was allowed to reach ASP.NET 10 and returned **200** with a **synthetic restricted document marker**. On ASP.NET 11 it returned 404.
- A second listener applied `path,url_dec -m beg /gate/` on port 5104. The identical absolute-form test was denied **403** on both versions. This is evidence for that fixture-specific mitigation, not a universal proof against bypasses or double-decoding variants.
- A separate endpoint at `/gate/auth-private-document` invoked ASP.NET `.RequireAuthorization()`. It returned **401** (10) or **404** (11) to the unauthenticated test; no application-level authentication bypass.

**Attacker could:** retrieve a resource that a real deployment protects **only through the same type of upstream path ACL**, where the application serves it without an independent authorization check. This is the most concrete unauthorized *proxy-policy* crossing in this suite. The document is artificial; no private customer record or real access control was tested.

**Cannot conclude:** Identity account takeover, access to an app-authenticated route, RCE, bypass of arbitrary HAProxy policies, or any novel root cause. The same parser inconsistency is documented in [Microsoft PR #65930](https://github.com/dotnet/aspnetcore/pull/65930), merged April 2026.
