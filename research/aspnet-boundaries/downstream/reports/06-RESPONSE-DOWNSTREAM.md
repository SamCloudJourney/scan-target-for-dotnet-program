# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## #6: ResponseCaching decoded-equals collision, fixed in .NET 11

**Source → sink:** query decoding → `ResponseCachingKeyProvider.CreateStorageVaryByKey` → vary-by-query key serialization → ResponseCaching middleware replay.

**New test:** exact same synthetic public variants and two-client ordering as #5, implemented using MVC `[ResponseCache(Duration=180,Location=Any,VaryByQueryKeys=new[]{"*"})]`. On .NET **10**, the second client requesting variant B received `PUBLIC RESPONSE;category=public-A;generation=1`. On .NET **11**, it correctly received `PUBLIC RESPONSE;category=public-B;generation=2`.

**Controls:** identical request repeats cache correctly, `Authorization` bypasses ordinary lookup, protected private response uses `Cache-Control: private` and separately returns Alice/Bob with anonymous 401. The framework's named vary serialization changed to a dedicated separator in .NET 11.

**Attacker could:** poison a public ResponseCaching representation's body/header for the colliding query shape on .NET 10, within the configured cache TTL. **Not demonstrated:** private data leakage, authentication bypass, write access, account takeover or RCE.

**Prior public fix:** [PR #68510](https://github.com/dotnet/aspnetcore/pull/68510). Not a novel report.
