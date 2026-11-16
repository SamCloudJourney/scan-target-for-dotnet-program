# ASP.NET Core boundary investigation — fourth and fifth passes

**Last updated:** 16 November 2026. Repository: `SamCloudJourney/scan-target-for-dotnet-program`. All tests: Linux GitHub-hosted runner, localhost/127.0.0.1 only; no production systems, third-party accounts, secrets or customer records.

## Confirmed matrix

| Candidate | .NET 10.0.15 | .NET 11.0.0 | Maximum demonstrated consequence |
|---|---|---|---|
| **#5 OutputCaching** | Wrong public body, ETag, CSP, client parse error and wrong 304 | Same | Public representation and security-header integrity confusion; no proved script execution |
| **#6 ResponseCaching** | Same-direction and reverse-direction public body/ETag collision; wrong 304 | Distinct representations; correct ETag and 200 on mismatched validator | Public cache-key integrity flaw on .NET 10, not private data leak |
| **#8 Kestrel + proxy** | Raw proxy-only ACL bypass for selected representations; normalized+decoded ACL prevents corpus success | Dot-segment mismatch with raw ACL; normalized+decoded ACL prevents corpus success | Synthetic proxy-policy crossing, not ASP.NET authentication bypass |

## Tests and evidence

| Workflow | Exact GitHub Actions run | Results |
|---|---|---|
| Fourth pass: validators, named vary and normalizer | [43825674348](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825674348) | 38/38 .NET 10; 38/38 .NET 11 |
| Fifth pass: bidirectional seeding and 23 path forms | [43826202135](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202135) | 16/16 .NET 10; 16/16 .NET 11 |
| Existing original boundary suite | [43826202113](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202113) | Successful both versions |
| Second-pass downstream controls | [43826202239](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202239) | Successful both versions |
| Third-pass broader normalization | [43826202080](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202080) | Successful both versions |
| Fourth pass repeated on the fifth commit | [43826202053](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826202053) | Successful both versions |

**70 percent stronger language is *not* justified:** The counts are assertions, many negative controls. No counts represent vulnerabilities or exploit success rates.

## More concrete HTTP consequences

1. **Wrong 304:** B's URL was given A's cached `ETag`. Requesting B with `If-None-Match` for that validator returned 304 rather than retrieving B's true representation (OutputCaching on both versions; ResponseCaching on .NET 10). In a separate stateful reverse-seeding control, a client first received B content on A's URL and then sent that issued B validator; 304 preserved the incorrect representation on A. 304 without the mismatched body/validator evidence is not security impact by itself.
2. **Client contract failure:** An intended JSON response was replaced with cached HTML; a JSON consumer failed parsing. Its noncolliding control parsed normally. This is a public endpoint integrity failure.
3. **CSP confusion:** B's `default-src 'self'` was returned in response to a query whose application representation would set `default-src 'none'`. That is a downgrade **of a response header**, not a proof that an attacker can inject script into a protected page.
4. **Named-vary protection:** Configuring output/response variation on the fixed decoded name `a` instead of wildcard query keys distinguished the tested pair on both releases.
5. **Authenticated protection:** Alice/Bob signed local cookie sessions to a `.RequireAuthorization()` route remained separate under the query collision; anonymous access returned 401. This is a concrete failed escalation attempt, not just an assumption.
6. **Proxy canonicalization:** The vulnerable raw-path ACL, HAProxy native normalizer and decoded path policy are different configurations. Both normalized+decoded and additional encoded-separator denial blocked the 23 tested path forms on both versions. A returned 404 may reflect backend routing rather than a proxy denial.

## Root cause, novelty and responsible disclosure

- #5's literal-equals query serializer and collision are already [public issue #68779](https://github.com/dotnet/aspnetcore/issues/68779) and [fix PR #68792](https://github.com/dotnet/aspnetcore/pull/68792) (August 2026).
- #6's delimiter design was already addressed via [PR #68510](https://github.com/dotnet/aspnetcore/pull/68510) (August 2026).
- #8's older HTTP/1 absolute-form encoded-slash inconsistency has public [PR #65930](https://github.com/dotnet/aspnetcore/pull/65930) (April 2026); the dot-segment proxy ACL mismatch is a more general HTTP request normalization/configuration issue, not demonstrated as novel to Microsoft.

**MSRC submission recommendation:** none of the three can be responsibly marketed as a novel Important/Critical ASP.NET Core vulnerability on this evidence. To qualify, a genuinely new root cause and an actual in-scope authorization/confidentiality boundary must be independently reproduced, not inferred from URL differences or public response replay.

## Reproduction code

- `research/aspnet-boundaries/downstream/Program.cs`: all synthetic endpoints
- `research/aspnet-boundaries/downstream/fourth_pass.py` and `fifth_pass.py`: test clients, positive and negative controls
- `research/aspnet-boundaries/downstream/haproxy-fourth.cfg` and `haproxy-fifth.cfg`: native normalizer comparisons
- `.github/workflows/aspnet-fourth-pass.yml` and `aspnet-fifth-pass.yml`: cross-version GitHub Actions matrices with raw JSON evidence uploads

The Microsoft and HAProxy source links are context, not evidence of a new unfixed defect.
