# New in PowerHub 2.0

PowerHub grew over the years from a small script™ meant for personal
experiments or even learning exercises to a tool that many people use, so
with version 2.0 come some well-deserved changes, like proper documentation,
packaging and a more fleshed-out implementation of some ideas I had in the
beginning.

## Documentation

Documentation is now hosted by GitHub pages; the GitHub wiki is disabled.

## Packaging

The `powerhub.py` and `requirements.txt` have been removed. The `setup.py`
has been replaced with a `setup.cfg`. PowerHub is now a first-class
Python package and should be treated as such. Like any other Python package,
it should be installed with `pip install`, which will place executables in
`~/.local/bin`.

## No more dev branch

Development will happen directly on the master branch. Releases will be
tagged and made available on PyPI. Installing directly from the repository
is not recommended, unless you want to test out the latest changes or you
want to contribute to the project. I will be less inclined to help out with
issues if you use a bleeding edge version. Bug reports will always be
welcome, though!

## Workspace directory

There is now a clearer separation of files that belong to the workspace
directory. To be precise, the database and most directories in
`$XDG_DATA_HOME/powerhub` have been moved into a new subdirectory named
`workspace`. As a side effect, this may make your clipboard and uploads
files appear empty. This fixes that (assuming `$XDG_DATA_HOME` is
undefined):

```console
$ cd ~/.local/share/powerhub
$ mv powerhub_db.sqlite upload webdav* workspace/
```

## PowerShell v2

PowerShell v2 is not supported anymore. It becomes less and less common and
the amount of effort it takes to make PowerHub run on v2 is not justified by
the benefit. Besides, AMSI does not exist in v2, so just load the modules
directly. PowerHub has the "Static List" feature for this.

## Key exchange

In PowerHub 1.0, the key was simply embedded in the stager. In principle,
this is a vulnerability, as specialized antivirus products could use the key
to inspect the higher order stages. PowerHub 2.0 performs a Diffie-Hellman
key exchange by default (but no server verification on top of the TLS
handshake) and also supports an out-of-band key exchange, meaning the key is
pasted on the command line.

## Pre-loaded modules

It's now possible to deliver the PowerHub payload with some modules
pre-loaded. This is interesting for environments without network access. If
the key is also embedded in the stager, you can deliver it manually e.g. via
USB to the target and use the modules.

## power-obfuscate

Installing PowerHub will yield a new executable: `power-obfuscate`. This
makes it possible to use the obfuscation techniques of PowerHub on arbitrary
PowerShell scripts or .NET executables without having to use the web
application.

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
