# New in PowerHub 2.0

PowerHub grew over the years from a small script™ meant for personal
experiments or even learning exercises to a tool that many people use, so
with version 2.0 come some well-deserved changes.

## Depreciation of Load-HubModule

It was confusing to have both `Load-HubModule` and `Get-HubModule`. We had
to execute the former to be able to use the latter. Now there is only
`Get-HubModule`. It performs lazy loading over the network when needed,
which means that the code of the module is transferred the first time you
execute `Get-HubModule` or if you explicitely pass the `-Reload` switch.

## Depreciation of the Loot tab

Dumping LSASS is too much of a moving target and should be left to specialty
tools. The idea was that dumping LSASS is possible with only
[LOLBINs](https://lolbas-project.github.io/), so it seemed like a small
addition to endow PowerHub with this capability, but things have gotten
complicated lately. AVs are quarantining the dump file, the LSASS process is
protected by various mechanisms, etc. It's better to use specialized tools
as outlined [here](https://s3cur3th1ssh1t.github.io/Reflective-Dump-Tools/)
and references therein.

## No more dev branch

Development will happen directly on the master branch. Releases will be
tagged and made available on PyPI. Installing directly from the repository
is not recommended, unless you want to test out the latest changes or you
want to contribute to the project. I will be less inclined to help out with
issues if you use a bleeding edge version. Bug reports will always be
welcome, though!

## Documentation

Documentation is now hosted by GitHub pages; the GitHub wiki is disabled.

## power-obfuscate

Installing PowerHub will yield a new executable: `power-obfuscate`. This
makes it possible to use the obfuscation techniques of PowerHub on arbitrary
PowerShell scripts or .NET executables without having to use the web
application.

## Pre-loaded modules

It's now possible to deliver the PowerHub payload with some modules
pre-loaded. This is interesting for environments without network access. If
the key is also embedded in the stager, you can deliver it manually e.g. via
USB to the target and use the modules.
