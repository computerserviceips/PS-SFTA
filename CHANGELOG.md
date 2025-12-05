# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 1.3.0 - 2025-12-04
### Added
- Provide detailed file association information via `Get-FTA -Detailed` and allow clearing user-specific associations with `Remove-FTA` without supplying a target application.
- Work around UCPD.sys protections by cloning PowerShell with a dynamically generated helper name when updating UserChoice entries.
- Document the new behaviors and usage in the README.
- Seed `UserChoiceLatest` alongside legacy `UserChoice` entries with the new machine-bound hash when Windows enables AppDefault hash rotation features.
- Optional `-SuppressNewAppAlert` switch to disable "new app installed" prompts by enforcing the `NoNewAppAlert` policy before writing associations (writing to HKCU and HKLM when elevated).
- Optional `-LogFile` and `-Silent` parameters to capture a transcript (defaulting to `%TEMP%` when only a filename is provided) and run unattended without console output.
- Optional `-AllowedGroup` parameter and `Set-FTAFromConfig` helper to scope associations to specific groups or bulk-apply mappings from a config file (including UNC paths).

### Fixed
- Seed `OpenWithProgids` for new associations to suppress the Windows user-choice prompt when the ProgId hash is already applied.
- Prevent log initialization and write failures from throwing invalid variable reference errors by formatting verbose messages safely.
- Suppress registry provider output when creating UserChoice and UserChoiceLatest entries so silent mode stays quiet.
- Harden UserChoice/UserChoiceLatest writes with a helper fallback so association updates don't fail when the temporary helper cannot create registry values.
- Use a registry API fallback that creates missing UserChoice/UserChoiceLatest keys directly when helper writes are blocked, avoiding missing-path and access errors.
- Preserve log history across config-driven runs, skip association writes when the requested ProgId and hashes are already present, and only restart `explorer.exe` once at the end of a batch when changes (or missing hashes) are applied.

### Changed
- Align licensing artifacts with the MIT license, retaining prior Danysys authorship alongside the updated 2025 Computerservice ips copyright.
- Restart `explorer.exe` after applying associations and provide clearer console guidance so users know when defaults are ready.

## 1.2.0 - 2022-04-17
### Added
- Refresh ApplicationAssociationToasts to avoid showing OpenWith.exe when no default application is selected for the first time.


## 1.1.0 - 2020-09-14
### Changed
- Hash Algorithm Raw Powershell Code


## 1.0.0 - 2020-09-08
### First Release
