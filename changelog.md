Version 1.4
===========

* New feature: Get-Loot transfers local credential information from the
  LSASS process, the SAM hive and other back to PowerHub
* New feature: executing clipboard entry content upon executing PowerHub on
  target

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
