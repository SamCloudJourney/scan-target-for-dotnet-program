# Third-pass: tested downstream effects and controls

This pass adds the real Chromium cookie-store check, a cacheable plain-text/JSON ResponseCaching variant, an HTML/JSON OutputCaching representation, and a broader HAProxy path comparison.

All tests occur on loopback 127.0.0.1. The HAProxy fixture exposes three local listeners:

- 5102: raw `path_beg /gate/` check (fragile)
- 5104: once-decoded `path,url_dec -m beg /gate/` check (fixes encoded slash but not traversal)
- 5105: once-decoded path-prefix check **and** denial of literal/once-decoded `/../` segments (passes only the eight specified test variants, not claimed universal)

The benign two-origin redirect receiver is port 5103. Cookie tests use local server port 5100.

One HTML ResponseCaching fixture did not cache even on a repeated same query, so it is a meaningful negative control, **not** proof of a cache-key fix. A separate cacheable plain-text/JSON fixture demonstrates the .NET 10 collision with `Age: 0`. OutputCaching can cache and replay HTML plus its content type/disposition/other headers to a JSON-designated query.

For detailed proof, see `reports/THIRD-PASS-CONCLUSIONS.md` and GitHub Actions artifacts. Original scan findings are proposals; do not file as novel MSRC reports based on known fixes or configuration-dependent proxies.
