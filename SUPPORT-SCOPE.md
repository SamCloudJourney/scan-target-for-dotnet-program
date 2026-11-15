# Scope and snapshot status

Status checked against Microsoft pages on November 15, 2026. Re-check official
scope, support status, and latest patches before every scan or submission.

## Direct MSRC .NET program scope

The [Microsoft .NET Bounty Program](https://www.microsoft.com/en-us/msrc/bounty-dot-net-core)
identifies:

- Current supported .NET and ASP.NET Core versions. As of the
  [support policy updated November 10, 2026](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core),
  these are .NET 11.0.0 (STS) and .NET 10.0.15 (LTS). Install the corresponding
  latest SDKs, 11.0.100 and 10.0.404.
- The latest ASP.NET Core 2.x when running on .NET Framework. The current
  source branch is `release/2.3`; its head is a servicing snapshot, not
  independently verified as the exact source for the latest shipped package.
  The program's wording is conditional; confirm applicability with MSRC.
- Templates shipped with supported .NET and ASP.NET Core.
- Associated GitHub Actions in associated .NET and ASP.NET Core repositories.
- Learn .NET documentation and embedded samples for supported versions,
  subject to the program's own terms and exclusions.

The supported version table places .NET 8 and .NET 9 out of support on
November 10, 2026. This repository does not include them as current targets.
The .NET 11 RC line ended go-live support when .NET 11 GA shipped November 10;
RCs and previews are therefore not included as current targets. The published
preview-scope list is stale (last updated in 2021); it lists no current .NET 10
or 11 preview feature. Do not infer new scope from that stale list.

The MSRC page also excludes out-of-support versions, classic .NET Framework
and ASP.NET Web Forms/MVC, and technologies not unique to .NET. It has
potentially conflicting language about documentation and samples; the program
terms control eligibility.

## Supplementary sources

The catalog's Aspire, MAUI, YARP, WCF, Extensions, standalone samples, and
standalone GitHub workflow snapshots are preserved for research convenience.
They are not independently promised in-scope by the .NET bounty page. A
supplementary component is relevant only where it is part of an in-scope
product and a finding satisfies the program's impact and rules.

## Version and completeness notes

- The .NET 11 VMR is pinned to `dotnet/dotnet` commit
  `297acf930fb0f5c07fd4e51d78e521b4ad2e5d1f` (`v11.0.100`).
- The .NET 10 VMR snapshots are pinned to `v10.0.404` and Microsoft's
  separately published `v10.0.115` source archive; both represent the
  November 10, 2026 .NET 10.0.15 servicing release. `v10.0.115` is not an
  unsupported .NET release.
- Other individual-source versions and workflow commit pins are listed in
  `ACQUIRED-SOURCES.json`. Workflow snapshots are not full source checkouts.
- Uploaded target catalog file counts are checked during acquisition. Archive
  SHA-256 values identify the downloaded GitHub source archives, not an
  upstream signed-release verification.
- Source trees may reference submodules, generated content, or external
  dependencies not present in the archive. This is a source snapshot, not a
  build-verified or vulnerability-verified product.
