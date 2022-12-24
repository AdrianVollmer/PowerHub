{# Load .NET assembly in memory and create alias for the function that executes it #}

$DotNetExec = {
    $Code = [System.Convert]::FromBase64String("{{code}}")
    $Assembly = [Reflection.Assembly]::Load([byte[]]$Code)
    $Assembly.EntryPoint.Invoke($Null, $args)
}

New-Item -Force -Path function: -Name "script:{{name}}" -Value $DotNetExec.GetNewClosure()
