#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, AzFilesHybrid
param(
    [Parameter(Mandatory = $true)]
    [System.String]$StorageAccountResourceID,
    [ValidateSet('ComputerAccount', 'ServiceLogonAccount')]
    [Parameter(Mandatory = $false)]
    [System.String]$DomainAccountType = 'ComputerAccount',
    [Parameter(Mandatory = $false)]
    [System.String]$OuDistinguishedName
)

$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'AzFilesHybrid'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-Verbose -Message 'Starting to import PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    $VerbosePreference = 'Continue'
    Write-Verbose -Message "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    $VerbosePreference = 'SilentlyContinue'
    Import-Module -Name $Module -Verbose:$false | Out-Null

    $i++
}

Write-Verbose -Message 'Finished importing PowerShell modules.'
$VerbosePreference = 'Continue'

# Navigate to where AzFilesHybrid is unzipped and stored and run to copy the files into your path
.\CopyToPSPath.ps1

# Ensures you do not inherit an AzContext in your runbook
Write-Verbose -Message 'Disabling Azure context autosave.'
Disable-AzContextAutosave -Scope Process

# Connect to Azure with system-assigned managed identity
[System.String]$FirstAzTenantID = '36c1c557-722b-4473-9ad4-95be51a5000d'
[System.String]$FirstAzSubscriptionID = '225d8fd1-bd45-4959-8ccf-28a626893d92'
[System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
Write-Verbose -Message $VerboseMessage
try {
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
}
catch {
    Write-Error -Message $_
}

Write-Verbose -Message 'Getting context.'
$GetAzContext = Get-AzContext
if (($AzSubscriptionID -eq $GetAzContext.Subscription.Id) -and ($AzTenantID -eq $GetAzContext.Tenant.Id)) {
    Write-Verbose -Message 'Current context equals context of VWAN and Firewall context. Continuing.'
}
else {
    Write-Verbose -Message "Setting context to Azure subscription ID: '$AzSubscriptionID' and Tenant ID: '$AzTenantID'."
    Get-AzSubscription -SubscriptionId $AzSubscriptionID -TenantId $AzTenantID | Select-AzSubscription
}

# Register the target storage account with your active directory environment under the target OU
# (for example: specify the OU with Name as "UserAccounts" or DistinguishedName as
# "OU=UserAccounts,DC=CONTOSO,DC=COM"). You can use this PowerShell cmdlet: Get-ADOrganizationalUnit
# to find the Name and DistinguishedName of your target OU. If you are using the OU Name, specify it
# with -OrganizationalUnitName as shown below. If you are using the OU DistinguishedName, you can set it
# with -OrganizationalUnitDistinguishedName. You can choose to provide one of the two names to specify
# the target OU. You can choose to create the identity that represents the storage account as either a
# Service Logon Account or Computer Account (default parameter value), depending on your AD permissions
# and preference. Run Get-Help Join-AzStorageAccountForAuth for more details on this cmdlet.

Join-AzStorageAccount `
    -ResourceGroupName $ResourceGroupName `
    -StorageAccountName $StorageAccountName `
    -SamAccountName $SamAccountName `
    -DomainAccountType $DomainAccountType `
    -OrganizationalUnitDistinguishedName $OuDistinguishedName `

# You can run the Debug-AzStorageAccountAuth cmdlet to conduct a set of basic checks on your AD configuration
# with the logged on AD user. This cmdlet is supported on AzFilesHybrid v0.1.2+ version. For more details on
# the checks performed in this cmdlet, see Azure Files Windows troubleshooting guide.
Debug-AzStorageAccountAuth -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName -Verbose