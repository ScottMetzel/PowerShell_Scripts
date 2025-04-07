#Requires -Version 5.1
#Requires -Modules ActiveDirectory,Az.Accounts, Az.Resources, AzFilesHybrid, DnsClient, NetSecurity, NetTCPIP, SmbShare
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.String]$StorageAccountResourceID,
    [ValidateSet('ComputerAccount', 'ServiceLogonAccount')]
    [Parameter(Mandatory = $false)]
    [System.String]$DomainAccountType = 'ComputerAccount',
    [ValidatePattern(
        '^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$'
    )]
    [Parameter(Mandatory = $false)]
    [System.String]$OUDistinguishedName,
    [Parameter(Mandatory = $false)]
    [ValidateSet('True', 'False')]
    [System.String]$DebugJoin = 'False'
)

$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'ActiveDirectory'
    'Az.Accounts',
    'Az.Resources',
    'AzFilesHybrid',
    'DnsClient',
    'NetSecurity'
    'NetTCPIP',
    'SmbShare'
)

## START: Importing PowerShell modules ##
[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-Verbose -Message 'Starting to import PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    $VerbosePreference = 'Continue'
    Write-Verbose -Message "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    $VerbosePreference = 'SilentlyContinue'
    Get-Module -Name $Module -ListAvailable -Verbose:$false | Import-Module -Verbose:$false -Force | Out-Null

    $i++
}

Write-Verbose -Message 'Finished importing PowerShell modules.'
$VerbosePreference = 'Continue'
## END: Importing PowerShell modules ##

## START: Resource ID Verification ##
[System.Collections.ArrayList]$RIDArray = $StorageAccountResourceID.Split('/')
[System.Int32]$RIDElementCount = $RIDArray.Count
[System.String]$Subscriptions = $RIDArray[1]
[System.String]$AzSubscriptionID = $RIDArray[2]
[System.String]$ResourceGroups = $RIDArray[3]
[System.String]$ResourceGroupName = $RIDArray[4]
[System.String]$Providers = $RIDArray[5]
[System.String]$ResourceProvider = $RIDArray[6]
[System.String]$StorageAccounts = $RIDArray[7]
[System.String]$StorageAccountName = $RIDArray[-1]
[System.String]$SamAccountName = $StorageAccountName

if (9 -ne $RIDElementCount) {
    Write-Error -Message "The supplied Resource ID: '$_' should have nine elements when split and does not."
    throw
}

if ('subscriptions' -ne $Subscriptions) {
    Write-Error -Message 'Subscription format validation failed.'
    throw
}

if (!([System.Guid]::TryParse($AzSubscriptionID, $([ref][System.Guid]::Empty)))) {
    Write-Error -Message 'Subscription ID format validation failed.'
    throw
}

if ('resourceGroups' -ne $ResourceGroups) {
    Write-Error -Message 'Resource Groups format validation failed.'
    throw
}

if ('providers' -ne $Providers) {
    Write-Error -Message 'Providers format validation failed.'
    throw
}

[System.String]$DesiredResourceProvider = 'Microsoft.Storage'
if ($DesiredResourceProvider -ne $ResourceProvider) {
    Write-Error -Message "The supplied Resource Provider: '$ResourceProvider' should be '$DesiredResourceProvider'."
    throw
}

if ('storageAccounts' -ne $StorageAccounts) {
    Write-Error -Message 'Machines format validation failed.'
    throw
}
## END: Resource ID Verification ##

# Ensures you do not inherit an AzContext in your runbook
Write-Verbose -Message 'Disabling Azure context autosave.'
Disable-AzContextAutosave -Scope Process

# Connect to Azure with system-assigned managed identity
[System.String]$FirstAzSubscriptionID = $AzSubscriptionID
[System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity. Context will be set to Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
Write-Verbose -Message $VerboseMessage
try {
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Environment 'AzureCloud' -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
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
    Write-Verbose -Message "Setting context to Azure subscription ID: '$AzSubscriptionID'."
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

Write-Verbose -Message "Joining storage account: '$StorageAccountName' to domain."
try {
    $ErrorActionPreference = 'Stop'
    Join-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -DomainAccountType $DomainAccountType -OrganizationalUnitDistinguishedName $OUDistinguishedName -SamAccountName $SamAccountName
}
catch {
    Write-Error -Message $_
    throw
}
# You can run the Debug-AzStorageAccountAuth cmdlet to conduct a set of basic checks on your AD configuration
# with the logged on AD user. This cmdlet is supported on AzFilesHybrid v0.1.2+ version. For more details on
# the checks performed in this cmdlet, see Azure Files Windows troubleshooting guide.
if ('True' -eq $DebugJoin) {
    Write-Verbose -Message "Debugging storage account: '$StorageAccountName' before domain join."
    try {
        $ErrorActionPreference = 'Stop'
        Debug-AzStorageAccountAuth -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName
    }
    catch {
        Write-Error -Message $_
        throw
    }
}
Write-Verbose -Message 'All done! Exiting.'