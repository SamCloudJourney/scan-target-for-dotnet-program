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

---

## Third validation pass — public representation and header substitution

A new public endpoint deliberately served an HTML body (`text/html`, `Content-Disposition: inline`, `X-Frame-Options: DENY`) for decoded query key `a`, while decoded key `a=B` was intended to produce JSON (`application/json`, `Content-Disposition: attachment; filename=public-B.json`, `X-Frame-Options: SAMEORIGIN`). Request `?a=B%3D` seeded the cache; `?a%3DB=` then received **the HTML content and all three seeded headers**, including an `Age: 0` cache-hit indicator.

**Versions:** reproduced on both ASP.NET Core 10.0.15 and 11.0.0. The request intended for JSON instead receives an HTML representation. This establishes a wrong-format and response-metadata integrity consequence, not stored XSS, cross-site scripting, credential theft, or remote code execution.

**Controls:** second-round authenticated Alice/Bob output endpoints remained separate; `Set-Cookie` responses were not cached; Authorization-bearing requests generated fresh content. [Third-pass CI](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822012995).

**Security readiness:** existing issue #68779 and fix #68792 mean this is not a novel discovery.


---

## Fourth and fifth validation: ETag, 304, reverse seeding and CSP

**Versions:** ASP.NET Core 10.0.15 (SDK 10.0.404) and 11.0.0 (SDK 11.0.100). All tests used only local synthetic representations and a fixed HTTP client.

**Fourth-pass ETag collision:** Client A requested `?a=B%3D` (key `a`, value `B=`) and got `ETag: "public-A-validator"`. A second client requested `?a%3DB=` (key `a=B`, empty value) and received **the same A validator** on both releases, despite application logic requiring B's validator. Sending `If-None-Match: "public-A-validator"` with the B URL generated **HTTP 304 Not Modified** instead of an independent B response.

**Downstream client effect:** A deliberately public endpoint returned HTML for A and JSON for B. After seeding A, a client expecting JSON from B instead received cached HTML; the standard JSON parser raised `JSONDecodeError`. A noncolliding B request parsed successfully. This is a real application-functionality failure, not automatically script execution or a vulnerability in the JSON parser.

**Fifth-pass reverse seeding:** Seeding B first made a subsequent A request receive B's exact body and `ETag: "fifth-B"` on **both** versions. A's intended CSP was `default-src 'none'`; B's stored CSP was `default-src 'self'`. The A request received B's less restrictive **CSP header**, proving that response security headers can be confused as part of public cache reuse. A subsequent `If-None-Match: "fifth-B"` request to the *victim A URL* received 304, showing the incorrect variant persists through client-initiated revalidation. This does **not** prove XSS, arbitrary script injection or private data access.

**Negative controls:** `SetVaryByQuery("a")` fixed-name policy kept both decoded query forms separate with independently generated bodies on **both** releases. Cookie-authenticated Alice/Bob requests to `.RequireAuthorization().CacheOutput("public-query-all")` remained separate; anonymous requests returned 401. These are real tested controls, not assumptions.

**Evidence:** [Fourth-pass run 43825674348](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825674348) (38/38 checks per version), [fifth-pass run 43826202135](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202135) (16/16 checks per version; mixed with proxy tests). Raw JSON includes every response status, header, body and control.

**Novelty and severity:** #5's original delimiter collision has prior public [issue #68779](https://github.com/dotnet/aspnetcore/issues/68779) and [fix PR #68792](https://github.com/dotnet/aspnetcore/pull/68792). The stronger HTTP consequences do not by themselves create a new underlying vulnerability or demonstrate Important/Critical impact.
