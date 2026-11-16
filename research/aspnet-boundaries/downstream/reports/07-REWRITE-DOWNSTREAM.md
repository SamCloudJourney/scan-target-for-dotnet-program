# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## #7: followed rewrite redirect reaches another local origin on .NET 10

**Source → sink:** `RewriteOptions.AddRedirect(@"^legacy/(.*)$", "/$1")` → `Regex.Match.Result()` → `RedirectRule` Location header. On .NET 11 `UrlNormalizer.CollapseLeadingSlashes` prevents a leading scheme-relative target for this rule.

**New test:** request the deliberately unsafe rewrite route with a leading path capture that resolves to a **second loopback origin**. On .NET 10 the app emitted `Location: //127.0.0.1:5103/receiver`; a separate client followed it, the loopback receiver recorded the request, and returned `LOCAL-SECOND-ORIGIN-REACHED`. On .NET 11 the app emitted `/127.0.0.1:5103/receiver`; the client stayed on the app origin and got 404. A second `/local/$1` fixed-prefix rule stayed local on both builds.

**Attacker could:** place an off-site navigation target in a genuine application-origin redirect URL **when the application installs an unsafe capture-first rule**. This can aid trust-based phishing in affected deployments. The experiment contains no external domain, OAuth state, credentials, token disclosure, JavaScript, or code execution.

**Prior public fix:** [PR #66961](https://github.com/dotnet/aspnetcore/pull/66961). Misconfiguration-dependent; not novel MSRC-ready.

---

## Third validation pass — query forwarding to a second origin

The loopback test used the deliberately unsafe regex rule and a benign `audit_marker=PUBLIC-FIXTURE` request query. On .NET 10, the application generated `Location: //127.0.0.1:5103/received?audit_marker=PUBLIC-FIXTURE` and an HTTP client followed it to the independent loopback receiver. The receiver recorded the marker in its query string. On .NET 11, the Location was rooted locally; the second origin received no request.

**Downstream conclusion:** the original request's query can travel with the external redirect in the affected configuration. That does not prove disclosure of any *unknown* secret: the example marker was already in the URL. An OAuth-token or credential leak would require an additional, separately demonstrated application-specific path that introduces confidential query data.

**Evidence:** [Third-pass CI](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822012995), request/response JSON plus independent receiver hits. Microsoft had already merged PR #66961.

