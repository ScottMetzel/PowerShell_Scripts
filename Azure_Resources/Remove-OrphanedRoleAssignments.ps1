param(
    [System.Boolean]$RemoveOrphanedRoleAssignments = $true,
    [ValidateSet('ServicePrincipal', 'User')]
    [System.String]$ConnectAs = 'ServicePrincipal',
    [ValidateScript(
        {
            try {
                [System.Guid]::Parse($_) | Out-Null
                $true
            }
            catch {
                $false
            }
        }
    )]
    [System.String]$TenantID = '',
    [System.String]$ServicePrincipalFirstAzSubscriptionID = ''
)

$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'

[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.Resources'
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

if ($ConnectAs -eq 'ServicePrincipal') {
    # Ensures you do not inherit an AzContext in your runbook
    if (($TenantID -in @($null, '')) -or ($ServicePrincipalFirstAzSubscriptionID -in @($null, ''))) {
        Write-Error -Message 'Script is configured to connect as a Service Principal, but no initial Entra ID Tenant ID nor Azure Subscription ID were provided. Please provide both values and re-run the script.'
        throw
    }
    Write-Verbose -Message 'Disabling Azure context autosave.'
    Disable-AzContextAutosave -Scope Process

    # Connect to Azure with system-assigned managed identity
    [System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $TenantID, ''' and Azure Subscription ID: ''', $ServicePrincipalFirstAzSubscriptionID, '''.')
    Write-Verbose -Message $VerboseMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $TenantID -Subscription $ServicePrincipalFirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}

Write-Verbose -Message 'Getting all Azure subscriptions.'
$GetAzSubscriptions = Get-AzSubscription -TenantId $TenantID | Sort-Object -Property Name, Id

[System.Int32]$i = 1
[System.Int32]$SubscriptionCount = $GetAzSubscriptions.Count

foreach ($AzSubscription in $GetAzSubscriptions) {
    [System.String]$AzSubscriptionName = $AzSubscription.Name
    [System.String]$AzSubscriptionId = $AzSubscription.Id
    [System.String]$ThisSubscriptionScope = [System.String]::Concat('/subscriptions/', $AzSubscriptionId)
    Write-Verbose -Message "Processing Subscription: '$AzSubscriptionName' with ID: '$AzSubscriptionId'. Subscription: '$i' of: '$SubscriptionCount'."
    try {
        $ErrorActionPreference = 'Stop'
        Select-AzSubscription -SubscriptionObject $AzSubscription

        Write-Verbose -Message 'Retrieving orphaned role assignments in Subscription.'
        [System.Collections.ArrayList]$OrphanedRoleAssignmentArray = @()
        Get-AzRoleAssignment | Where-Object -FilterScript { ($null -eq $_.DisplayName) -and ($null -eq $_.SignInName) -and ($ThisSubscriptionScope -eq $_.Scope) } | ForEach-Object -Process {
            $OrphanedRoleAssignmentArray.Add($_) | Out-Null
        }

        [System.Int32]$j = 1
        [System.Int32]$OrphanedRoleAssignmentCount = $OrphanedRoleAssignmentArray.Count
        if (0 -lt $OrphanedRoleAssignmentCount) {
            Write-Warning -Message "Found the following: '$OrphanedRoleAssignmentCount' orphaned role assignments in Subscription:"
            foreach ($RoleAssignment in $OrphanedRoleAssignmentArray) {
                Get-AzRoleAssignment -ObjectId $RoleAssignment.ObjectId
                [System.String]$RoleAssignmentName = $RoleAssignment.RoleAssignmentName
                [System.String]$RoleAssignmentDisplayName = $RoleAssignment.DisplayName
                [System.String]$RoleAssignmentSignInName = $RoleAssignment.SignInName
                [System.String]$RoleAssignmentScope = $RoleAssignment.Scope
                [System.String]$RoleAssignmentRoleDefinitionName = $RoleAssignment.RoleDefinitionName
                Write-Verbose -Message "Role Assignment Name: '$RoleAssignmentName', Role Assignment Display Name: '$RoleAssignmentDisplayName', Role Assignment Sign-in Name: '$RoleAssignmentSignInName'. Role Assignment Scope: '$RoleAssignmentScope', Role Assignment Definition Name: '$RoleAssignmentRoleDefinitionName'."
            }

            if ($true -eq $RemoveOrphanedRoleAssignments) {
                Write-Verbose -Message "Removing orphaned role assignments in Subscription: '$AzSubscriptionId'."

                foreach ($RoleAssignment in $OrphanedRoleAssignmentArray) {
                    [System.String]$RoleAssignmentObjectID = $RoleAssignment.ObjectId
                    [System.String]$RoleAssignmentRoleDefinitionName = $RoleAssignment.RoleDefinitionName
                    [System.String]$RoleAssignmentScope = $RoleAssignment.Scope
                    Write-Warning -Message "Removing orphaned role assignment with Object ID: '$RoleAssignmentObjectID' and Role Definition Name: '$RoleAssignmentRoleDefinitionName' from Subscription: '$AzSubscriptionId'. Assignment: '$j' of: '$OrphanedRoleAssignmentCount'."
                    try {
                        $ErrorActionPreference = 'Stop'
                        Remove-AzRoleAssignment -ObjectId $RoleAssignmentObjectID -RoleDefinitionName $RoleAssignmentRoleDefinitionName -Scope $RoleAssignmentScope
                    }
                    catch {
                        Write-Error -Message "Failed to remove role assignment with ObjectId: '$($RoleAssignment.ObjectId)'. Error: $_"
                        throw
                    }

                    $j++
                }
            }
            else {
                Write-Verbose -Message "Skipping removal of orphaned role assignments in Subscription: '$AzSubscriptionId' since: 'RemoveOrphanedRoleAssignments' is set to: $($RemoveOrphanedRoleAssignments)."
            }
        }
        else {
            Write-Verbose -Message "No orphaned role assignments found in Subscription: '$AzSubscriptionId'."
        }
    }
    catch {
        Write-Error -Message "Failed to process Subscription: '$AzSubscriptionId'. Error: $_"
    }

    $i++
}
Write-Verbose -Message 'All done! Exiting.'