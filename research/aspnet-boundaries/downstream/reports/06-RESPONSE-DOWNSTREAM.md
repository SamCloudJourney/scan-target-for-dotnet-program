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

---

## Third validation pass — cacheable content-type and header variation

Two deliberately distinct fixtures produced different observations. An HTML-versus-JSON ResponseCaching endpoint with additional disposition and frame headers **was not cached** in this specific run; repeated same-shape requests were freshly generated, and the B request received JSON on both framework releases. The static body alone had initially masked that miss; the final test now includes a generation counter and does not claim HTML/JSON poisoning for that fixture.

A second, demonstrably *cacheable* fixture served `text/plain` for A and `application/json` for B, with distinct `X-Lab-Format` and `X-Lab-Download` values. The first A result was reused for the identical request. On **.NET 10.0.15**, the colliding B request received A's `text/plain` body and `X-Lab-Format: plain-A` header, with `Age: 0`. On **.NET 11.0.0**, it correctly received JSON and B's header. This is a real public content-type/header collision, subject to a cacheable representation and the usual cache policy.

**Controls:** authenticated/private-response isolation and no-cache handling as previously tested. [Third-pass CI](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822012995). No private account contents were exposed. Existing PR #68510 precedes these tests.


---

## Fourth and fifth validation: conditional HTTP cache integrity

**Fourth-pass ETag:** In an explicitly cacheable wildcard-query ResponseCaching fixture, .NET **10.0.15** returned public A's `ETag: "response-A-validator"` on a distinct B query, then answered B + `If-None-Match: "response-A-validator"` with **HTTP 304**. On .NET **11.0.0**, B received `"response-B-validator"` and the mismatched If-None-Match returned **200**. These results show validator and conditional-response integrity effects beyond wrong body text.

**Fifth-pass reverse seeding:** Client B seeded `?a%3DB=` and the subsequent A `?a=B%3D` received B's body and `ETag: "fifth-response-B"` on .NET 10. A request to that A URL carrying the **ETag actually issued to it** returned 304. On .NET 11, A instead received `"fifth-response-A"` with its own body; its 304 for that own validator is correct. Thus the collision is bidirectional on 10, while 11's query serialization separates the requests.

**Negative controls:** A fixed named `VaryByQueryKeys = {"a"}` cache kept the two requests' representations separate on both versions. Authorization-bearing requests bypassed ordinary public cache reuse in the earlier suite; protected private controllers served their respective identities and anonymous requests remained 401. The ResponseCaching tests did not expose private account contents.

**Evidence:** [Fourth-pass runner evidence](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825674348) (38/38 each version); [fifth-pass runner evidence](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202135) (16/16 each version).

**Prior work:** [Microsoft PR #68510](https://github.com/dotnet/aspnetcore/pull/68510) already addresses the encoded-equals collision class. Public cache validator misuse on an already-known collision does not prove a separate new root cause, account takeover, or RCE.
