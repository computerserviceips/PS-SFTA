# PowerShell SFTA

[![Latest Version](https://img.shields.io/badge/Latest-v1.3.0-green.svg)]()
[![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)]()
[![Made with Love](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red.svg?colorB=11a9f7)]()


PowerShell Set File/Protocol Type Association Default Application Windows 10/11


## Features
* Set File Type Association.
* Set Protocol Association.
* Get File Type Association.
* List File Type Association.
* Remove File Type Association.
* Get Protocol Type Association.
* List Protocol Type Association.
* Register Application.
* Unregister Application.
* Apply multiple file associations from a configuration file with optional group-based targeting.

## Usage
##### Type Get-Help command for information
```powershell
Get-Help .\SFTA.ps1 -full
```

## Basic Usage

##### Set Acrobat Reader DC as Default .pdf reader:
```powershell
Set-FTA AcroExch.Document.DC .pdf

```

##### Set Sumatra PDF as Default .pdf reader:
```powershell
Set-FTA Applications\SumatraPDF.exe .pdf

```

##### Set Acrobat Reader DC for .pdf only when the user is in "Adobe Acrobat Users":
```powershell
Set-FTA AcroExch.Document.DC .pdf -AllowedGroup "Adobe Acrobat Users"

```

##### Apply associations from a config file (UNC paths supported):
```powershell
Set-FTAFromConfig \\mydomain.local\fileshare\SetUserFTAconfig.txt -LogFile SFTA.log -Silent

```

Config file lines use comma-separated values:

```
.pdf, AcroExch.Document.DC, GRP_Adobe_Reader
```

The third value (group) is optional. Lines starting with `#` or blank lines are ignored. Quote group names with spaces when calling `Set-FTA` directly; config files can omit the quotes.

##### Read the current .pdf association including the registry hash:
```powershell
Get-FTA -Extension .pdf -Detailed

```

##### Remove a custom or user-specific association for .pdf:
```powershell
Remove-FTA -Extension .pdf -ExtensionOnly

```


##### Set Google Chrome as Default for http Protocol:
```powershell
Set-PTA ChromeHTML http

```

##### Register Application and Set as Default for .pdf reader:
```powershell
Register-FTA "C:\SumatraPDF.exe" .pdf -Icon "shell32.dll,100"

```

### Notes

- Windows KB5034765 introduced a UCPD.sys protection that blocks registry writes to `UserChoice` keys for some extensions and protocols. SFTA now writes those values through a dynamically named temporary copy of `powershell.exe` to ensure associations can be updated successfully.
- When a ProgId has not previously been recorded for an extension, SFTA also seeds the corresponding `OpenWithProgids` entry so Windows does not prompt to pick an app even though the `UserChoice` hash is already present.
- Windows Insider builds have begun migrating associations into `UserChoiceLatest` with a new machine-bound hash (`AppDefaultHashRotation` / `AppDefaultHashRotationUpdateHashes`). SFTA now writes that companion hash and `ProgId` branch when a machine ID is available so new protections don’t ignore freshly-set defaults.
- Pass `-SuppressNewAppAlert` to disable the "new app installed" default-assignment prompts by setting the `NoNewAppAlert` policy flag for the current user (and HKLM when elevated) before writing associations.
- Capture a run log via `-LogFile <path>`; if you pass only a filename (no directory), the log is written to your `%TEMP%` directory. Combine this with `-Silent` to run unattended without console output while still writing a transcript.
- After setting associations, SFTA now restarts `explorer.exe` to immediately apply the new defaults in the shell and file picker dialogs.
- Use `-AllowedGroup` (or specify a group on each config line) to scope an association update to members of a specific local or domain group.

## Additional Instructions

##### Set Microsoft Edge as Default .pdf reader from Windows Command Processor (cmd.exe):
```powershell
powershell -ExecutionPolicy Bypass -command "& { . .\SFTA.ps1; Set-FTA 'MSEdgePDF' '.pdf' }"

```

##### Set Sumatra PDF as Default .pdf reader from Windows Command Processor (cmd.exe):
```powershell
powershell -ExecutionPolicy Bypass -command "& { . .\SFTA.ps1; Set-FTA 'Applications\SumatraPDF.exe' '.pdf' }"

```

##### Set Sumatra PDF as Default .pdf reader from Windows Command Processor (cmd.exe) (Load Script From GitHub Raw URL):
```powershell
powershell -ExecutionPolicy Bypass -command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/master/SFTA.ps1'));Set-FTA 'Applications\SumatraPDF.exe' '.pdf' }"

```



## Release History
See [CHANGELOG.md](CHANGELOG.md)


<!-- ## Acknowledgments & Credits -->


## License

Usage is provided under the [MIT](https://choosealicense.com/licenses/mit/) License.

Copyright © 2022, Danysys. <danysys.com>
Copyright © 2025, Computerservice ips
