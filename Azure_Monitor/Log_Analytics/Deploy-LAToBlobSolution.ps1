# Requires Azure PowerShell and Bicep!

param (
    [System.String]$ARMTemplateFilePath = '.\main.bicep',
    [System.String]$AzSubscriptionID,
    [System.String]$Location = 'westus2',
    [ValidateSet(
        'Demo',
        'Dev',
        'Test',
        'Staging',
        'Prod',
        IgnoreCase = $true
    )]
    [System.String]$EnvironmentName = 'Demo',
    [System.String]$ValidationLevel = 'Provider'
)
[System.Collections.Hashtable]$ARMTemplateParameterObject = @{
    'location'        = $Location;
    'environmentName' = 'Demo';
    'instanceCount'   = 1;
}

$GetARMTemplateFile = Get-Item -Path $ARMTemplateFilePath
$GetARMTemplateFileBaseName = $GetARMTemplateFile.BaseName
$GetARMTemplateFilePath = $GetARMTemplateFile.ResolvedTarget
[System.String]$DateTime = Get-Date -Format FileDateTime
[System.String]$DeploymentName = [System.String]::Concat($GetARMTemplateFileBaseName, '_', $DateTime)

Get-AzSubscription -SubscriptionId $AzSubscriptionID | Set-AzContext

New-AzDeployment -Name $DeploymentName -Location $Location -TemplateFile $GetARMTemplateFilePath -TemplateParameterObject $ARMTemplateParameterObject -ValidationLevel $ValidationLevel -Verbose