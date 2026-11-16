# Fourth-pass tests — source-independent downstream consequences

This pass runs a fixed, bounded, loopback-only corpus on ASP.NET Core 10.0.15 and
11.0.0 using GitHub Actions. It does not test live Microsoft services.

- **#5 OutputCaching**: Collision affects ETag and server-side conditional
  requests (304); test a simulated JSON consumer receiving HTML; verify
  fixed-named query variation avoids the particular name/value collision;
  exercise actual authenticated cookie sessions across colliding queries.
- **#6 ResponseCaching**: Same ETag/If-None-Match test on explicitly
  cacheable response; negative control with named-key variation and current
  .NET 11; do not infer confidentiality leaks.
- **#8 Kestrel/HAProxy**: Compare raw prefix ACL, HAProxy's documented
  `normalize-uri percent-decode-unreserved strict` followed by dot segment
  canonicalization, and normalization plus `url_dec` prefix authorization.
  The normalized policy uses unconditional normalizer directives to avoid
  ambiguity. Preserve backend authorization checks on all three ports.

The fixtures demonstrate public-response integrity failures and unsafe proxy
ACL configurations, not account takeover or arbitrary private data access.
Tests record all response headers, statuses, bodies and controls.
