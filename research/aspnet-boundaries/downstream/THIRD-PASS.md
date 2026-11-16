# Third-pass boundary consequence testing — local only

Additional experiments that extend the verified second-pass fixture.
Both .NET 10.0.15 (SDK 10.0.404) and .NET 11.0.0 (SDK 11.0.100).

1. Cookie: Python stdlib CookieJar parses the *actual* request-derived
   authentication Set-Cookie value, records domain/path and checks whether it
   would attach to an unrelated application-root path. This is not a full
   Chromium/Firefox browser acceptance test.
2. Caches: public HTML-vs-JSON query semantics deliberately yield different
   `Content-Type`, `Content-Disposition`, X-Frame-Options, and bodies. Checks
   show whether a colliding client's request receives *all* of the first
   client's cached representation, not just its string body.
3. Redirect: follow a benign synthetic query marker via a scheme-relative
   redirect to a second 127.0.0.1-only origin; record destination request.
   This is not a demonstration of real OAuth token disclosure.
4. Proxy/Kestrel: run an eight-case path-normalization suite across HAProxy
   raw and one-level decoded ACLs, and enumerate any returned synthetic
   documents. Any unanticipated 200 requires analysis, not a vulnerability
   designation.

The framework's own `.RequireAuthorization()` controls are covered by the
previous round; this additional suite does not assert an auth bypass.
Only selected local ports 5100/5102/5103/5104 are reachable by the fixture.
