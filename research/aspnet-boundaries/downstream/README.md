# ASP.NET Core downstream-impact laboratory — second validation pass

Scope: only GitHub-hosted runners and loopback 127.0.0.1, no real accounts,
external destinations, actual personal records, or Microsoft infrastructure.

Reproduction: run `.github/workflows/aspnet-downstream-impact.yml` (SDK 10.0.404 and
11.0.100) or build ImpactFixture.csproj and run the loopback-only `impact_test.py`
with HAProxy configured using `haproxy-impact.cfg`.

Attack models and negative controls:
1. **Cookie Path**: Test encoded and unencoded semicolon, CRLF and comma in a
   *trusted* X-Forwarded-Prefix, compare auth/antiforgery/TempData cookie
   headers to an intentionally unsafe *application-configured* explicit Path.
   Untrusted peer is denied header influence.
2. **OutputCaching**: Seed a public synthetic variant, request a distinct
   query structure from a second client, and check wrongly reused body and
   X-Lab-Variant response header. Also test Authorization, Set-Cookie and
   authenticated private endpoints as protective controls.
3. **ResponseCaching**: Same cross-client public variant test, plus
   authenticated private response with explicit `Cache-Control: private`.
4. **Rewrite**: Resolve and *follow* a scheme-relative redirect only to a
   local second origin, and contrast a fixed-prefix rewrite.
5. **Kestrel**: Compare HAProxy's raw `path_beg` check against a hardened
   decoded-path check; confirm only a synthetic proxy-only document is
   accessible under .NET 10 and application-level authorization still works.

Failing tests are evidence needing diagnosis, not an authorization to report a
vulnerability. Existing upstream disclosures must be considered independently.
No content in this repository is an exploit against a real target.
