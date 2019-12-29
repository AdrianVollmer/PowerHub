Version 1.4
===========

* New feature: Automatically load 'profile.ps1' from data home at the end of
  the payload
* New feature: Get-Loot transfers local credential information from the
  LSASS process, the SAM hive and other back to PowerHub
* New feature: executing clipboard entry content upon executing PowerHub on
  target
* New feature: Offer options in the download cradle builder
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
===========

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
