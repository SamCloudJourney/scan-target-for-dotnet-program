# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## #5: OutputCaching cross-client public response substitution

**Source → sink:** parsed/decode query pairs → wildcard `SetVaryByQuery("*")` → cache key with literal `=` name/value separator → shared lookup/storage → body and response-header reuse.

**New test:** first simulated client requests `?a=B%3D` (decoded key `a`, value `B=`, public variant A), then a separate client requests `?a%3DB=` (decoded key `a=B`, empty value, variant B). In **both** 10.0.15 and 11.0.0 the second client received `PUBLIC OUTPUT;category=public-A;generation=1` and the seed's `X-Lab-Variant: public-A`. Thus the downstream integrity impact is not just identical key strings: the wrong public body **and metadata** are actually served across clients.

**Controls:** same query cached, `Authorization` header generates fresh public content rather than retrieving the seed, Set-Cookie response is not cached, authenticated Alice/Bob private endpoints return separate identity bodies, and anonymous private request returns 401. No privilege boundary was crossed in the protected endpoint.

**Attacker could:** seed a public response variant that other unauthenticated visitors receive when they request a distinct colliding query shape during cache lifetime, potentially misleading clients that trust the output. **Not demonstrated:** read private cache entries, alter persistent state, execute script or take over a user; those would require additional independently vulnerable application content/policy.

**Novelty blocker:** [existing issue #68779](https://github.com/dotnet/aspnetcore/issues/68779) and [fix #68792](https://github.com/dotnet/aspnetcore/pull/68792). The tested releases still show the issue despite the public main-branch fix.
