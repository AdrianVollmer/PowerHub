<#
.Description
This function stores the already exported configuration to file, so this
information isn't lost when the export encounters an issue

.Functionality
Internal
#>
function Save-M365DSCPartialExport
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Content,

        [Parameter(Mandatory = $true)]
        [System.String]
        $FileName
    )

    $tempPath = Join-Path -Path $env:TEMP -ChildPath $FileName
    $Content | Out-File -FilePath $tempPath -Append:$true -Force
}
