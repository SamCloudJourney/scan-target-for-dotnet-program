# .NET source research set

Organized upstream source snapshots for local research. This is an independent
mirror, not a Microsoft repository. Snapshot inclusion is not a statement that
every component is bounty-eligible. Follow the [Microsoft .NET Bounty
Program](https://www.microsoft.com/en-us/msrc/bounty-dot-net-core) and its
rules; confirm the latest version and commit before each review.

## Start here

1. Read [SUPPORT-SCOPE.md](SUPPORT-SCOPE.md) to select current, supported targets
   and distinguish program scope from supplementary sources.
2. Read [AI-SCANNING.md](AI-SCANNING.md) before using an automated agent.
3. Use [TARGET-COVERAGE.md](TARGET-COVERAGE.md) to map the supplied target list.
4. Use [ACQUIRED-SOURCES.json](ACQUIRED-SOURCES.json) as the pinned source index.
   It records upstream repository, ref, commit, location, regular-file count,
   and downloaded archive SHA-256.

## Layout

- `scan-target-v11.0.100/`: .NET 11.0.0 / SDK 11.0.100 VMR source.
- `sources/dotnet-vmr-v10.0.404/`: .NET 10.0.15 / SDK 10.0.404 VMR snapshot.
- `release-sources/dotnet-vmr-v10.0.115/`: Microsoft-published .NET 10.0.15 /
  SDK 10.0.115 released-source snapshot.
- `release-sources/dotnet-10.0.15/`: individual .NET 10 runtime, ASP.NET Core,
  EF Core, WPF, WinForms, and Windows Desktop repositories.
- `release-sources/aspnetcore-2.3-servicing/`: current ASP.NET Core 2.3
  servicing branch snapshot (branch head; not asserted to be the exact source
  commit for the latest published NuGet package).
- `supplemental-targets/`, `documentation-and-samples/`, and
  `workflow-snapshots/`: catalogued release, documentation, sample, and
  workflow snapshots. Workflow snapshots contain workflow/pipeline files only.

No scans or source builds are started by preparing this repository.
