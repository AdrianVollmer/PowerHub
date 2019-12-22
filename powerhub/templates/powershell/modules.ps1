$Modules = @()
{% if modules %}
{% for m in modules %}
    $m = New-Object -TypeName PSObject
    $m.PsObject.TypeNames.Add("PowerHub.Module")
    {% for key, value in m.__dict__().items() %}
        Add-Member -InputObject $m -memberType NoteProperty -name "{{key}}" -value "{{value}}"
    {% endfor %}
    $m | Add-Member MemberSet PSStandardMembers $PSStandardMembers
    $defaultDisplaySet = 'ShortName','Name','Type','N'
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    $Modules += $m
{% endfor %}
{% endif %}
