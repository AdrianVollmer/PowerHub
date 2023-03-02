Changelog
=========

All notable changes to this project will be documented in this file.

## [Unreleased]

## [2.0.1] - 2023-03-02

### Fixed

* Syntax issues with non-default AMSI bypasses

## [2.0.0] - 2023-02-26

### Added

* Many more options for the download cradle
* The `power-obfuscate` command
* An authenticated WebDAV share
* Ability to allowlist IP adresses

### Changed

* Clipboard entries must be marked for execution
* Changes to the modules on disk are automatically recognized
* Default locations of the database, upload directory, webdav directories
  and static directory

### Removed

* The Loot tab
* PowerShell v2 support
* The `Load-HubModule` command has been replaced by `Get-HubModule`
* The `powerhub.py` executable


Version 1.11
------------

* Change: Merge `Load-HubModule` into `Get-HubModule`
* Change: Determine module type by magic bytes instead of directories
* Fix: Load certificate chains (#51)
* Add: aliases for PE and .NET executables

Version 1.10
------------

* Fix: When using `SeparateAMSI`, the clipboard entry was ignored
* Change: Use AES instead of slow RC4 after the AMSI bypass has been applied
* Add: Parameter `-OutFile` to `Run-DotNETExe`
* Fix: Set default argument to `Run-DotNETExe`
* Add: static files view (@exploide)

Version 1.9
-----------

* Add: Separate AMSI Bypass

Version 1.8-2
-------------

* Fix: Defeat Defender
* Fix: Update socket.io

Version 1.8-1
-------------

* Fix: Make compatible with PS2
* Fix: Bypass newest Windows Defender

Version 1.8
-----------

* Change: Obfuscate more parts of the PowerShell stager
* Change: Always apply Rasta Mouse's AMSI bypass after the first bypass in
  order to make loading of assemblies possible
* Fix: Make `Get-SysInfo` more robust in case a Cmdlet is missing

Version 1.7
-----------

* New feature: Place everything but the modules and generated certificates
  in a workspace directory
* Change: Bypass new malware detection by Windows Defender

Version 1.6
-----------

* New feature: Ability to generate payloads on the fly (exe, .NET, vbs)
* Change: Use bootstrap toasts instead of messages
* Change: Include more information in Get-SysInfo
* Change: Use AES instead of RC4 in some cases for more performance
* Change: Clean up dependencies and add `setup.py`

Version 1.5
-----------

* New feature: Ability to either open files in the File Exchange in browser or
  download them
* New feature: A 'static' directory, so PowerHub can be used to serve static files
* Fix: Things didn't work if `$XDG_DATA_HOME` was non-empty

Version 1.4
-----------

* New feature: Automatically load 'profile.ps1' from data home at the end of
  the payload
* New feature: Get-Loot transfers local credential information from the
  LSASS process, the SAM hive and other back to PowerHub
* New feature: executing clipboard entry content upon executing PowerHub on
  target
* New feature: Offer options in the download cradle builder
* New feature: Clipboard entries are now editable
* Let the user choose the AMSI bypass (several included)
* New feature: certificate pinning for self-sigend certs
* PushTo-Hub now encrypts the data before sending it
* Made the PowerShell code more idiomatic (look out for changes in
  Load-HubModule, Run-Exe, Run-Shellcode and Run-DotNETExe)
* Cleaned up the PowerShell output (#40)
* Removed the Receiver from the web interface, as the feature proved to be
  not ready yet
* Refactor some code for internal improvements

Version 1.3
-----------

* Change WebDAV directory structure to allow for proper read/write access
* Move all user directories to `$XDG_DATA_HOME/.local/share/powerhub` to
  enable usage on multi user systems
* Return module object on Load-HubModule so it can be passed to Run-Exe and
  similar commands
* Add Save-HubModule
* Obfuscate reverse shell traffic
* Ensure PowerShell v2 compatibility
* On the event of an incoming shell, the entry is faded in nicely in the
  webapp. (#31)
* Made command line parameters more persistent:
  -p -> -lp
  -l -> -lh
  -u -> -up
* Use a random password if neither '--auth' nor '--no-auth' are given.
* Generate a self-signed certificate if the user does not provide one. This
  way, SSL/TLS can be enabled by default.
