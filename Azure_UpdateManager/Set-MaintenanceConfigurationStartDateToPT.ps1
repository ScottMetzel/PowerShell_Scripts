<#
    .SYNOPSIS
    This script updates an Azure Update Manager Maintenance Configuration to start on the next Patch Tuesday.

    .DESCRIPTION
    This script updates an Azure Update Manager Maintenance Configuration to start on the next Patch Tuesday.

    It maintains the time of day of the existing Maintenance Configuration, but updates the date to the next Patch Tuesday, which allows for more complex maintenance windows to be created, such as one which repeats for certain days of a week, but only after patch Tuesday.
    It is designed to be run as an Azure Automation Runbook using a System-Assigned Managed Identity.

    You could probably update it to run in a PowerShell-based Azure Function as well.

    Be sure to fill in the Tenant ID and Subscription ID of your Azure Automation Account on lines 107 and 108, respectively.

    It requires the Az.Accounts, Az.Resources, Az.Maintenance, and PowerShell Utility modules.

    This script is provided AS-IS with no warranties or claims it'll work as described. Please review the code and test in a safe environment.
    Executing this script is done at your own risk ;) .

    .NOTES
    ===========================================================================
    Created with: 	Microsoft Visual Studio Code
    Created on:   	01/08/2025 6:17 PM
    Created by:   	Scott Metzel
    Organization: 	-
    Filename:     	Enable-WindowsServerManagementByAzureArc.ps1
    Comments:     	This script builds on Kevin Sullivan's original script, here:
                    https://github.com/kevinsul/arc-ws-sa-enable/blob/main/arc-ws-sa-enable.ps1
    ===========================================================================

    .PARAMETER MaintenanceConfigurationRIDs
    Supply the Resource IDs of Maintenance Configurations to update. If not supplied, all Maintenance Configurations in the current Azure context will be updated.
    Multiple Resource IDs can be supplied by separating them with commas.
    .PARAMETER SafetyNetBeforeDays
    Supply the number of days before Patch Tuesday to start updating Maintenance Configurations. Defaults to -1, which is one day before Patch Tuesday.
    .PARAMETER SafetyNetAfterDays
    Supply the number of days after Patch Tuesday to start updating Maintenance Configurations. Defaults to 1, which is one day after Patch Tuesday.

    .PARAMETER StartDateDayOffset
    Supply the number of days to offset the start date of the Maintenance Configuration. Defaults to 0, which means no offset.

    .PARAMETER RunAsRunbookOrScript
    Supply whether the script is running as a Runbook or a Script. Defaults to 'Runbook', which will connect to Azure using a System-Assigned Managed Identity.

    .EXAMPLE
    # Unfiltered
    PS> Connect-AzAccount
    PS> .\Set-MaintenanceConfigurationStartDateToPT.ps1

    .EXAMPLE
    # Specific Maintenance Configurations
    PS> Connect-AzAccount
    PS> .\Set-MaintenanceConfigurationStartDateToPT.ps1 -MaintenanceConfigurationRIDs '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/Microsoft.Maintenance/maintenanceConfigurations/{configuration-name}'

    .OUTPUTS
    System.String
#>
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.Maintenance
param(
    [Parameter(Mandatory = $false)]
    [System.String]$MaintenanceConfigurationRIDs = '',
    [Parameter(Mandatory = $false)]
    [System.Int32]$SafetyNetBeforeDays = -1,
    [Parameter(Mandatory = $false)]
    [System.Int32]$SafetyNetAfterDays = 1,
    [Parameter(Mandatory = $false)]
    [System.Int32]$StartDateDayOffset = 0,
    [Parameter(Mandatory = $false)]
    [ValidateSet(
        'Runbook',
        'Script'
    )]
    [System.String]$RunAsRunbookOrScript = 'Runbook'
)
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.Maintenance'
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

if ($RunAsRunbookOrScript -eq 'Runbook') {
    Write-Verbose -Message 'Running as an Azure Automation Runbook.'
    # Ensures you do not inherit an AzContext in your runbook
    Write-Verbose -Message 'Disabling Azure context autosave.'
    Disable-AzContextAutosave -Scope Process

    # Connect to Azure with system-assigned managed identity
    [System.String]$FirstAzTenantID = ''
    [System.String]$FirstAzSubscriptionID = ''
    [System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-Verbose -Message $VerboseMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}
else {
    Write-Verbose -Message 'Running as a script.'
}

$Now = Get-Date
$NextMonth = $Now.AddMonths(1)

$FirstDayThisMonth = Get-Date -Year $Now.Year -Month $Now.Month -Day 1 -Hour 0 -Minute 0 -Second 0
$FirstTuesdayThisMonth = $FirstDayThisMonth.AddDays((([DayOfWeek]::Tuesday - $FirstDayThisMonth.DayOfWeek + 7) % 7))
$PatchTuesdayThisMonth = $FirstTuesdayThisMonth.AddDays(7)

$FirstDayNextMonth = Get-Date -Year $NextMonth.Year -Month $NextMonth.Month -Day 1 -Hour 0 -Minute 0 -Second 0
$FirstTuesdayNextMonth = $FirstDayNextMonth.AddDays((([DayOfWeek]::Tuesday - $FirstDayNextMonth.DayOfWeek + 7) % 7))
$PatchTuesdayNextMonth = $FirstTuesdayNextMonth.AddDays(7)

# Determine if now is one day before the next month's Patch Tuesday
if ($Now.AddDays($SafetyNetBeforeDays) -lt $PatchTuesdayNextMonth) {
    Write-Verbose -Message "The current date is before Patch Tuesday next month, which is: $PatchTuesdayNextMonth, with the supplied offset of: $SafetyNetBeforeDays."
    [System.Boolean]$IsBeforePatchTuesdayNextMonth = $true
}
else {
    Write-Verbose -Message "The current date is after Patch Tuesday next month, which is: $PatchTuesdayNextMonth, with the supplied offset of: $SafetyNetBeforeDays. Not updating Maintenance Configurations."
    [System.Boolean]$IsBeforePatchTuesdayNextMonth = $false
}

# Determine if now is one day after the current month's Patch Tuesday
if ($Now.AddDays($SafetyNetAfterDays) -gt $PatchTuesdayThisMonth) {
    Write-Verbose -Message "The current date is after Patch Tuesday this month, which is: $PatchTuesdayThisMonth, with the supplied offset of: $SafetyNetAfterDays."
    [System.Boolean]$IsAfterPatchTuesdayThisMonth = $true
}
else {
    Write-Verbose -Message "The current date is before Patch Tuesday this month, which is: $PatchTuesdayThisMonth, with the supplied offset of: $SafetyNetAfterDays. Not updating Maintenance Configurations."
    [System.Boolean]$IsAfterPatchTuesdayThisMonth = $false
}

$PatchTuesdayTable = [ordered]@{
    PatchTuesdayThisMonth         = $PatchTuesdayThisMonth;
    PatchTuesdayNextMonth         = $PatchTuesdayNextMonth;
    IsBeforePatchTuesdayNextMonth = $IsBeforePatchTuesdayNextMonth;
    IsAfterPatchTuesdayThisMonth  = $IsAfterPatchTuesdayThisMonth;
}

# Split the MaintenanceConfigurationRIDs parameter into an array
if ($PSBoundParameters.ContainsKey('MaintenanceConfigurationRIDs')) {
    [System.String[]]$MaintenanceConfigurationRIDsArray = $MaintenanceConfigurationRIDs.Split(',')
}

[System.Int32]$i = 1
[System.Int32]$RIDCount = $MaintenanceConfigurationRIDs.Count

if (($true -eq $PatchTuesdayTable.IsAfterPatchTuesdayThisMonth) -and ($true -eq $PatchTuesdayTable.IsBeforePatchTuesdayNextMonth)) {
    Write-Verbose -Message "The current date is between Patch Tuesdays using the before offset of: $SafetyNetBeforeDays and the after offset of: $SafetyNetAfterDays."

    if ($PSBoundParameters.ContainsKey('MaintenanceConfigurationRIDs') -and $MaintenanceConfigurationRIDsArray.Count -gt 0) {
        Write-Verbose -Message "Updating Maintenance Configurations to start on the next Patch Tuesday, which is: $($PatchTuesdayTable.PatchTuesdayNextMonth)"
        foreach ($RID in $MaintenanceConfigurationRIDsArray) {
            Write-Verbose -Message "Processing Maintenance Configuration RID: '$RID'. RID: '$i' of: '$RIDCount' RIDs."
            [System.String]$RIDResourceGroupName = $RID.Split('/')[4]
            [System.String]$RIDName = $RID.Split('/')[-1]

            Write-Verbose -Message "Getting Maintenance Configuration with RID: $RID"
            $GetMaintenanceConfiguration = Get-AzMaintenanceConfiguration -ResourceGroupName $RIDResourceGroupName -Name $RIDName

            Write-Verbose -Message 'Getting current StartDateTime time value.'
            [System.String]$CurrentStartDateTime = $GetMaintenanceConfiguration.StartDateTime
            [System.String]$CurrentStartDateTimeTime = $GetMaintenanceConfiguration.StartDateTime.Split(' ')[-1]

            Write-Verbose -Message "Current StartDateTime time value is: $CurrentStartDateTimeTime"

            if (0 -lt $StartDateDayOffset) {
                Write-Verbose -Message "The supplied StartDateDayOffset value is: $StartDateDayOffset. Adjusting start date by this offset."
                [System.DateTime]$NewStartDate = Get-Date -Date $PatchTuesdayNextMonth -Format 'yyyy-MM-dd'
                [System.String]$NewStartDateWithOffset = $NewStartDate.AddDays($StartDateDayOffset).ToString('yyyy-MM-dd')
                [System.String]$NewStartDateTime = [System.String]::Concat($NewStartDateWithOffset, ' ', $CurrentStartDateTimeTime)
            }
            else {
                Write-Verbose -Message "The supplied StartDateDayOffset value is: $StartDateDayOffset. Not adjusting start date."
                [System.String]$NewStartDate = (Get-Date -Date $PatchTuesdayNextMonth -Format 'yyyy-MM-dd').ToString()
                [System.String]$NewStartDateTime = [System.String]::Concat($NewStartDate, ' ', $CurrentStartDateTimeTime)
            }

            if ($CurrentStartDateTime -ne $NewStartDateTime) {
                Write-Verbose -Message "Current StartDateTime time value of: $CurrentStartDateTime is different than the new StartDateTime time value of: $NewStartDateTime. Updating Maintenance Configuration."

                Write-Verbose -Message "Setting StartDate property value to: $NewStartDateTime"
                $GetMaintenanceConfiguration.StartDateTime = $NewStartDateTime

                Write-Verbose -Message "Updating Maintenance Configuration with RID: $RID"
                try {
                    $ErrorActionPreference = 'Stop'
                    Update-AzMaintenanceConfiguration -ResourceGroupName $RIDResourceGroupName -Name $RIDName -Configuration $GetMaintenanceConfiguration -Verbose
                }
                catch {
                    $_
                    Write-Error -Message "Failed to update Maintenance Configuration with RID: $RID"
                    throw
                }
            }
            else {
                Write-Verbose -Message "Current StartDateTime time value of: $CurrentStartDateTime is the same as the new StartDateTime time value of: $NewStartDateTime. Not updating Maintenance Configuration."
            }
            $i++
        }
    }
    else {
        Write-Verbose -Message "Getting all Maintenance Configurations and updating them to start on the next Patch Tuesday, which is: $PatchTuesdayNextMonth"
        Write-Verbose -Message 'Getting all Maintenance Configurations'
        $GetMaintenanceConfigurations = Get-AzMaintenanceConfiguration

        foreach ($MaintenanceConfiguration in $GetMaintenanceConfigurations) {
            [System.String]$RID = $MaintenanceConfiguration.Id
            Write-Verbose -Message "Processing Maintenance Configuration RID: '$RID'. RID: '$i' of: '$RIDCount' RIDs."
            [System.String]$RIDResourceGroupName = $RID.Split('/')[4]
            [System.String]$RIDName = $RID.Split('/')[-1]

            Write-Verbose -Message "Getting Maintenance Configuration with RID: $RID"
            $GetMaintenanceConfiguration = Get-AzMaintenanceConfiguration -ResourceGroupName $RIDResourceGroupName -Name $RIDName

            Write-Verbose -Message 'Getting current StartDateTime time value.'
            [System.String]$CurrentStartDateTime = $GetMaintenanceConfiguration.StartDateTime
            [System.String]$CurrentStartDateTimeTime = $GetMaintenanceConfiguration.StartDateTime.Split(' ')[-1]

            Write-Verbose -Message "Current StartDateTime time value is: $CurrentStartDateTimeTime"

            if (0 -lt $StartDateDayOffset) {
                Write-Verbose -Message "The supplied StartDateDayOffset value is: $StartDateDayOffset. Adjusting start date by this offset."
                [System.DateTime]$NewStartDate = Get-Date -Date $PatchTuesdayNextMonth -Format 'yyyy-MM-dd'
                [System.String]$NewStartDateWithOffset = $NewStartDate.AddDays($StartDateDayOffset).ToString('yyyy-MM-dd')
                [System.String]$NewStartDateTime = [System.String]::Concat($NewStartDateWithOffset, ' ', $CurrentStartDateTimeTime)
            }
            else {
                Write-Verbose -Message "The supplied StartDateDayOffset value is: $StartDateDayOffset. Not adjusting start date."
                [System.String]$NewStartDate = (Get-Date -Date $PatchTuesdayNextMonth -Format 'yyyy-MM-dd').ToString()
                [System.String]$NewStartDateTime = [System.String]::Concat($NewStartDate, ' ', $CurrentStartDateTimeTime)
            }

            if ($CurrentStartDateTime -ne $NewStartDateTime) {
                Write-Verbose -Message "Current StartDateTime time value of: $CurrentStartDateTime is different than the new StartDateTime time value of: $NewStartDateTime. Updating Maintenance Configuration."

                Write-Verbose -Message "Setting StartDate property value to: $NewStartDateTime"
                $GetMaintenanceConfiguration.StartDateTime = $NewStartDateTime

                Write-Verbose -Message "Updating Maintenance Configuration with RID: $RID"
                try {
                    $ErrorActionPreference = 'Stop'
                    Update-AzMaintenanceConfiguration -ResourceGroupName $RIDResourceGroupName -Name $RIDName -Configuration $GetMaintenanceConfiguration -Verbose
                }
                catch {
                    $_
                    Write-Error -Message "Failed to update Maintenance Configuration with RID: $RID"
                    throw
                }
            }
            else {
                Write-Verbose -Message "Current StartDateTime time value of: $CurrentStartDateTime is the same as the new StartDateTime time value of: $NewStartDateTime. Not updating Maintenance Configuration."
            }
            $i++
        }
    }
}
else {
    Write-Verbose -Message "The current date is not between Patch Tuesdays using the before offset of: $SafetyNetBeforeDays and the after offset of: $SafetyNetAfterDays. Not updating Maintenance Configurations."
}
Write-Verbose -Message 'All done!'