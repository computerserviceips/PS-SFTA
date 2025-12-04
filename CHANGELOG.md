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

### Changed
- Align licensing artifacts with the MIT license, retaining prior Danysys authorship alongside the updated 2025 Computerservice ips copyright.

## 1.2.0 - 2022-04-17
### Added
- Refresh ApplicationAssociationToasts to avoid showing OpenWith.exe when no default application is selected for the first time.


## 1.1.0 - 2020-09-14
### Changed
- Hash Algorithm Raw Powershell Code


## 1.0.0 - 2020-09-08
### First Release
