$PowerHubModules = @()
{% if modules %}
{% for m in modules %}
    $m = New-Object -TypeName PSObject
    $m.PsObject.TypeNames.Add("PowerHub.Module")
    {% for key, value in m.__dict__().items() %}
        Add-Member -InputObject $m -memberType NoteProperty -name "{{key}}" -value "{{value}}"
    {% endfor %}

    {#
        set default members - does not work in PSv2:
        https://stackoverflow.com/questions/1369542/
    #}
    $m | Add-Member MemberSet PSStandardMembers $PSStandardMembers -Force
    $defaultDisplaySet = 'Name','Type','N','Loaded'
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    $m | Add-Member -MemberType ScriptMethod -Name ToString -Value {$this.Name} -PassThru -Force
    $PowerHubModules += $m
{% endfor %}
{% endif %}
