# Downstream impact validation: second pass

Date: 2026-11-16. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. Build matrix: .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and SDK 11.0.100 / ASP.NET Core 11.0.0. Both ran on Linux GitHub-hosted workers, 127.0.0.1 only.

**Result:** 35/35 independent downstream assertions passed for each version, 70/70 total. [CI run and original artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677873). First run had 34/35 on each version owing to a double-escaped *assertion regex*, not a target failure; it was corrected. The earlier root harness temporarily failed to compile because the project glob included the new nested source; the explicit project exclusion restored the old suite and it passed at [run 43817677930](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817677930).

Not a claim of 70 vulnerabilities. Test assertions cover positive, negative, and cross-version controls. Every identity, document, and token is fixture-only. Authorized tests never contacted any production site or third-party service.

Reproduce using `impact_test.py` and `haproxy-impact.cfg`. Raw result JSON, Kestrel logs, HAProxy logs, exact SDK and proxy versions are available in artifact `aspnet-downstream-net10` and `aspnet-downstream-net11` attached to the run (artifact retention 30 days). 

## #4: request-derived cookie Path, authentication, antiforgery and TempData

**Source → sink:** trusted `X-Forwarded-Prefix` → `ForwardedHeadersMiddleware` → `Request.PathBase` → `RequestPathBaseCookieBuilder` / Antiforgery / MVC TempData → `CookieOptions.Path` → `Set-Cookie` serializer.

**New tests:** raw and percent-encoded semicolons, an encoded CRLF string, comma, double-encoded semicolon; untrusted peer negative control; three distinct cookie producers. Result: 8 relevant security checks passed per version, plus an explicit application-configuration control. No separate `Domain=example.test` cookie attribute arose through the untrusted value in any request-derived producer. The semicolon escaped in the resulting cookie Path even in tested .NET 10.

**Important discriminator:** a deliberately unsafe **application-authored** `CookieOptions.Path = "/;Domain=example.test"` produced `Set-Cookie: fixture.explicit=no-secret; path=/;Domain=example.test; httponly`. This shows that the raw serializer trusts **developer-chosen** path text, but does not prove an attacker can reach the serializer with that text through the claimed `X-Forwarded-Prefix` chain. The test never sent cookies to example.test and did not test real browser cookie acceptance.

**Attacker could:** influence `PathBase` when allowed by a trusted proxy; potentially alter ordinary cookie scope as a consequence of the application's proxy path mapping. **Not demonstrated:** cookie domain injection, browser cookie theft, session fixation, account takeover or HTTP response splitting. The explicit-path counterexample requires unsafe application control of cookie options. Microsoft already has public [cookie hardening](https://github.com/dotnet/aspnetcore/commit/a4866158cce1a2015e08fe0732e7f41b74423215).

**Disposition:** original exploit thesis not reproduced; no MSRC readiness.

---

## Third validation pass — browser cookie handling (16 November 2026)

This stage added actual Chrome/Chromium DevTools cookie-store checks instead of relying only on response-header inspection or Python's cookie jar. For the accepted trusted-prefix string `/;Domain=example.test`, both tested ASP.NET Core releases emitted a cookie Path of `/%3BDomain=example.test`. Chromium stored one **host-only**, **HttpOnly** cookie for `127.0.0.1`, did not interpret `example.test` as a separate cookie Domain, and did not attach the cookie to the unrelated `/whoami` path. It was eligible for the encoded path `/%3BDomain=example.test/whoami`.

**Evidence:** the Chromium loopback test passed 6/6 assertions on .NET 10 and 6/6 on .NET 11. [Browser CI run](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306490); the Python CookieJar path/domain control and source-to-sink checks also passed. Cookie values are redacted in the latest public evidence.

**Security consequence:** changing the trusted prefix can change the ordinary *path scope* of a session cookie, which may affect an application's sign-in continuity under inconsistent proxy path configurations. It does **not** demonstrate domain widening, cookie exfiltration, session takeover, or a general browser vulnerability.

**Disposition unchanged:** original attribute-injection claim was refuted for these controls; previously published Microsoft hardening exists.

