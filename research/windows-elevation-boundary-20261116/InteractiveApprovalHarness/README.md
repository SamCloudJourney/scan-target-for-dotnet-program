# .NET Windows workload elevation — interactive UAC verification kit

**Scope:** A disposable Windows VM that you own. The test requires **two existing Windows identities**, an ordinary user and an administrator, and **two actual, separate administrator UAC approvals**. It does not bypass UAC and it does not deploy, repair, remove, or modify any real third-party software. Only uniquely generated, self-authored fixtures are used.

## Proven already by GitHub-hosted CI

- The exact snapshot's normal client obtains its trusted root from `Path.GetTempPath()`, launches `dotnet workload elevate --client-temp "…"` using `Verb="runas"`, and opens IPC pipes.
- The normal client derives `data/msi.json` from an extracted package directory and derives repair/uninstall product codes from workload package metadata or workload records.
- Elevated broker dispatch supports broader `CachePayload`, `RepairMsi`, `UninstallMsi` and dependency provider operations.
- The disposable standard-user ACL smoke passed: a normal user created a random temp extraction folder in a broad root while an administrator-only sibling remained unreadable, including via a user-created junction.
- The C# harness compiled on Windows Server 2022 and all PowerShell scripts parsed successfully.

These checks **do not prove** an exploit through an unmodified `dotnet workload` command. Source-provenance checks use the repository's .NET **11.0.100** source snapshot, not a distinct source tree for .NET 10.

## Requirements

1. An **isolated Windows VM** with .NET SDK **11.0.100** and the SDK under test (**11.0.100 or 10.0.404**). A supported Windows Server or Windows desktop VM should work; our compile smoke used Windows Server 2022.
2. Two **existing** local Windows accounts: `LabUser` (not an administrator) and `LabAdmin` (administrator), with permission from the VM owner. Do not run the client as an administrator.
3. PowerShell 7, a local checkout of this research branch accessible to **both** users, and optional WiX Toolset v3 (`candle.exe`, `light.exe`) for the unrelated, self-authored MSI test.
4. A human able to approve the **two** Windows UAC prompts as `LabAdmin`. Do not automate or fake consent.

**Safety:** Confirm the VM is disposable and Windows Update is not actively being serviced. The SDK broker can interact with the Windows Update Agent. The preparation script fails closed if it detects the Windows Update service running.

## Procedure

From a PowerShell session elevated as **LabAdmin**, navigate to the `InteractiveApprovalHarness` directory and run:

```powershell
.\Prepare-InteractiveFixture.ps1 -StandardUser "YOURVM\LabUser" -SdkVersion "11.0.100"
```

Copy the printed `FIXTURE_CONFIG` path. Setup creates one randomized sandbox under `C:\Users\Public\msrc-windows-elevation-lab-<random>`, two administrator-protected dummy data files, a standard-user writable client directory, and optionally a self-authored MSI fixture. Use `-SkipMsi` when WiX v3 is unavailable.

Sign in as **LabUser** (normal PowerShell, without elevation), navigate to the same scripts, and run:

```powershell
.\Run-InteractiveClient.ps1 -FixtureConfig "C:\Users\Public\msrc-windows-elevation-lab-<random>\client\fixture.json"
```

An administrator must consciously approve each real UAC prompt after verifying that this is the expected `dotnet.exe` on the disposable VM. The client will first use the *narrow* root for #12 and isolated #13 operations, then the *broad* root for #11. Cancelling either prompt is a valid negative control.

The low-client evidence is saved under `<sandbox>\client\results\interactive-<SDK>.json`.

Afterwards, sign back in as **LabAdmin** and independently inspect the protected source, cache hashes, ACLs, MSI state and HKLM fixture:

```powershell
.\Verify-And-Cleanup.ps1 -FixtureConfig "C:\Users\Public\msrc-windows-elevation-lab-<random>\client\fixture.json" -EvidenceDirectory "C:\LabEvidence"
```

Preserve the exported evidence and record the **actual date, time, Windows account names/SIDs, UAC prompt outcome, and installed SDK hashes**. Never include passwords or credential input in screenshots.

To delete *only* the random lab objects after preserving evidence:

```powershell
.\Verify-And-Cleanup.ps1 -FixtureConfig "C:\Users\Public\msrc-windows-elevation-lab-<random>\client\fixture.json" -EvidenceDirectory "C:\LabEvidence" -Cleanup
```

Repeat with a fresh fixture for SDK `10.0.404`.

## What each test can prove

| Candidate | Positive evidence under a genuine UAC-approved custom client | Still missing for MSRC |
|---|---|---|
| **#12** — Junction escape | Protected manifest/payload relocation through standard-user junction; low-user readback matches the protected hash | Same unexpected path produced by an **unmodified** workload command |
| **#13** — MSI authorization | Low-user IPC instructs approved broker to remove **only** an unrelated self-authored installed MSI; registry provider change succeeds | A legitimate workload operation authorizes a different MSI product than the approved workload |
| **#11** — Root provenance | Broad-root session relocates protected data independently of a junction; narrow direct-path control fails | Unmodified workload client's actual extracted `msi.json` path can be diverted to a protected file |

### Crucial distinction

This harness intentionally **uses the real Windows UAC mechanism but a custom low-user IPC client**. Even if everything passes, do **not** call it a confirmed exploit reachable through the unmodified `dotnet workload install/update/repair` CLI. The normal workload client constructs package IDs, manifest paths and product codes in a constrained way; reachability requires a separate demonstration. Do not classify as Critical or Important EoP solely from this kit.

## Repository artifacts and current limits

- Source audit: `ordinary-client-reachability-audit.ps1` (15 exact pinned-source assertions).
- CI workflow: `.github/workflows/disposable-windows-interactive-readiness.yml`.
- Separate earlier synthetic cross-SID experiments are on branch `research/windows-elevation-cross-sid-synthetic-20261116`.
- Genuine headless `runas` tests timed out without an administrator; no unattended GitHub-hosted runner supplied interactive approval.
- Possible overlap with published .NET workload file/junction security advisories remains an independent novelty assessment.

Please coordinate any suspected novel exploit with Microsoft Security Response Center before publishing further operational exploit details.
