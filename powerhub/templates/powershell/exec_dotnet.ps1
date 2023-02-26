{# Load .NET assembly in memory and function that executes it #}

function {{name}} {
    $Code = [System.Convert]::FromBase64String("{{code}}")
    $Assembly = [Reflection.Assembly]::Load([byte[]]$Code)
    $Arguments = New-Object -TypeName System.Collections.ArrayList
    $Arguments.add([String[]]$args)
    $Assembly.EntryPoint.Invoke($Null, $Arguments.ToArray())
}
