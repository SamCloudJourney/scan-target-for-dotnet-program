# Target list crosswalk

The supplied target list is mapped to the pinned source snapshots below.
Paths are repository-relative. Current direct MSRC program scope is defined in
`SUPPORT-SCOPE.md`; being present in this crosswalk alone does not make an item
in-scope.

| Supplied target | Source location |
|---|---|
| .NET Runtime — CoreCLR, Mono, JIT, GC and base libraries | `scan-target-v11.0.100/src/runtime`; .NET 10 current runtime: `release-sources/dotnet-10.0.15/runtime` |
| ASP.NET Core | `scan-target-v11.0.100/src/aspnetcore`; .NET 10: `release-sources/dotnet-10.0.15/aspnetcore` |
| .NET SDK | `scan-target-v11.0.100/src/sdk`; .NET 10 VMR snapshots: `sources/dotnet-vmr-v10.0.404/` and `release-sources/dotnet-vmr-v10.0.115/` |
| Entity Framework Core | `scan-target-v11.0.100/src/efcore`; .NET 10: `release-sources/dotnet-10.0.15/efcore` |
| Roslyn — C# and Visual Basic compilers | `scan-target-v11.0.100/src/roslyn` |
| F# | `scan-target-v11.0.100/src/fsharp` |
| MSBuild | `scan-target-v11.0.100/src/msbuild` |
| NuGet Client | `scan-target-v11.0.100/src/nuget-client` |
| .NET Diagnostics | `scan-target-v11.0.100/src/diagnostics` |
| WPF | `scan-target-v11.0.100/src/wpf`; .NET 10: `release-sources/dotnet-10.0.15/wpf` |
| Windows Forms | `scan-target-v11.0.100/src/winforms`; .NET 10: `release-sources/dotnet-10.0.15/winforms` |
| Windows Desktop | `scan-target-v11.0.100/src/windowsdesktop`; .NET 10: `release-sources/dotnet-10.0.15/windowsdesktop` |
| Arcade | `scan-target-v11.0.100/src/arcade` |
| Mono.Cecil | `scan-target-v11.0.100/src/cecil` |
| System.CommandLine | `scan-target-v11.0.100/src/command-line-api` |
| Deployment Tools | `scan-target-v11.0.100/src/deployment-tools` |
| Emscripten SDK integration | `scan-target-v11.0.100/src/emsdk` |
| .NET Scenario Tests | `scan-target-v11.0.100/src/scenario-tests` |
| Source Build Assets | `scan-target-v11.0.100/src/source-build-assets` |
| Source Link | `scan-target-v11.0.100/src/sourcelink` |
| Symbol Reader | `scan-target-v11.0.100/src/symreader` |
| Visual Studio Test Platform (VSTest) | `scan-target-v11.0.100/src/vstest` |
| XML Document Transform (XDT) | `scan-target-v11.0.100/src/xdt` |
| Aspire | `supplemental-targets/microsoft--aspire--v13.6.5--release` |
| YARP Reverse Proxy | `supplemental-targets/dotnet--yarp--v2.3.0--release` |
| WCF Client | `supplemental-targets/dotnet--wcf--v10.1.0-rtm--release` |
| .NET Platform Extensions | `supplemental-targets/dotnet--extensions--v11.0.0--release` |
| .NET MAUI | `supplemental-targets/dotnet--maui--11.0.10--release` and `supplemental-targets/dotnet--maui--10.0.130--release` |
| .NET Documentation | `documentation-and-samples/dotnet--docs--main--documentation` |
| ASP.NET Core Documentation | `documentation-and-samples/dotnet--AspNetCore.Docs--main--documentation` |
| .NET Samples | `documentation-and-samples/dotnet--samples--main--samples` |
| Aspire Samples | `documentation-and-samples/microsoft--aspire-samples--main--samples` |
| Aspire Documentation Website | `documentation-and-samples/microsoft--aspire.dev--main--documentation` |
| GitHub Actions and Azure pipeline definitions | `workflow-snapshots/`; these are workflow/pipeline files only, not full source trees |

The supported legacy ASP.NET Core 2.3 servicing snapshot is
`release-sources/aspnetcore-2.3-servicing`. It is an additional target not
listed in the uploaded target list; see the caveat in `SUPPORT-SCOPE.md`.
