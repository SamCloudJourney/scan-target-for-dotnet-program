# Third-pass ASP.NET Core boundary validation — 2026-11-16

**Validated test environment:** .NET SDK 10.0.404 / ASP.NET Core 10.0.15 and .NET SDK 11.0.100 / ASP.NET Core 11.0.0, Linux GitHub-hosted runners, loopback-only HAProxy and a second local HTTP origin.

**Latest final passing workflows**

- [Third-pass behavior/proxy and MIME suite](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306390): **29/29 per SDK**, 58/58 assertions.
- [Chromium cookie scope](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306490): **6/6 per SDK**, 12/12 assertions.
- [Original boundary regression suite](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306422): success on both SDKs.
- [Second-pass downstream suite](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306400): success on both SDKs.

All added fixtures use artificial identities, document content and benign markers. No external services or actual customer data were tested. Signed cookie values are redacted from the final public test results.

## Ranking by demonstrated downstream consequence

| Rank | Case | Specific attacker outcome observed | Version(s) | Independent defensive controls |
|---|---|---|---|---|
| 1 | #8 Kestrel/proxy | A path accepted by the proxy-only ACL resolves to the synthetic restricted backend route; includes dot-segment forms on .NET 10 **and 11** | Both for dot segments; .NET 10 only for encoded absolute-form %2F | Strict local HAProxy dot-segment deny blocks all eight fixed variants; backend authorization independently rejects |
| 2 | #5 OutputCaching | A response supposed to be JSON is served as cached **HTML**, with the seed's inline disposition, frame header and body | Both | Cookie-setting and authorized private output excluded from cache reuse |
| 3 | #6 ResponseCaching | A cacheable JSON-designated request is served **text/plain** body plus wrong format header, due to a colliding vary key | .NET 10 | .NET 11 corrected; one HTML-case response was never cached; private controls held |
| 4 | #7 Rewrite redirect | Browser/client navigation could be redirected off the application origin and propagate original benign query parameters | .NET 10 | .NET 11 collapses leading slashes; fixed-prefix rewrite stays local |
| 5 | #4 Cookie Path | No hostile Cookie Domain attribute established; Chromium stored host-only HttpOnly cookie under percent-encoded path | Neither | Trusted-proxy scope, path encoding, browser scope, untrusted source filtering |

The numeric order is **observed local effect**, not a CVSS ranking. #7 and #8 are particularly dependent on insecure/insufficient application or proxy authorization configurations; #5 and #6 are public-response integrity issues under cache-enabled endpoints.

## Distinguish old Microsoft defects from new zero-days

- #4: [cookie escaping commit](https://github.com/dotnet/aspnetcore/commit/a4866158cce1a2015e08fe0732e7f41b74423215), 10 Nov 2026.
- #5: [OutputCaching issue #68779](https://github.com/dotnet/aspnetcore/issues/68779), [fix #68792](https://github.com/dotnet/aspnetcore/pull/68792), Aug 2026.
- #6: [ResponseCaching fix #68510](https://github.com/dotnet/aspnetcore/pull/68510), Aug 2026.
- #7: [Rewrite fix #66961](https://github.com/dotnet/aspnetcore/pull/66961), Jun 2026.
- #8: [Kestrel absolute-form %2F fix #65930](https://github.com/dotnet/aspnetcore/pull/65930), Apr 2026. Dot-segment normalization is a distinct more general proxy-policy mismatch and needs a separate novelty/ownership analysis. [HAProxy ACL documentation](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/custom-rules/acls/) describes path prefix policy; HAProxy does not normalize URIs automatically.

**MSRC readiness:** none of these tests demonstrates a novel Important/Critical ASP.NET vulnerability, RCE, credential theft, browser XSS, or app-level auth bypass. Do not equate a proxy-only synthetic route with a framework authentication-bypass zero-day. Report a new case only after a previously undisclosed root cause and qualifying in-scope impact is independently established.

## Source files and raw evidence

- `research/aspnet-boundaries/downstream/Program.cs`, `third_pass.py`, `chrome_cookie_scope.mjs`, `haproxy-impact.cfg`
- `.github/workflows/aspnet-third-pass.yml` and `.github/workflows/aspnet-cookie-browser.yml`
- [Raw third-pass runner artifacts](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306390)
- [Raw Chromium cookie metadata](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822306490)
