# Requires Az.OperationalInsights
# Connect-AzAccount beforehand
### START: GET LA ###
param(
    [Parameter(
        Mandatory = $true
    )]
    [ValidateScript(
        {
            $ObjectGuid = [System.Guid]::empty
            [System.Guid]::TryParse($_,[System.Management.Automation.PSReference]$ObjectGuid)

        }
    )]
    [System.String]$EntraTenantID,
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$LAWResourceID,
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$LATableName,
    [Parameter(
        Mandatory = $true
    )]
    [ValidateScript(
        {
            [System.DateTime]$NewDateTime = $_
            $NewDateTime
        }
    )]
    [System.String]$FromDateTimeUTC,
    [Parameter(
        Mandatory = $true
    )]
    [ValidateScript(
        {
            [System.DateTime]$NewDateTime = $_
            $NewDateTime
        }
    )]
    [System.String]$ToDateTimeUTC,
    [System.Int32]$SliceMinutes = 15,
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$StorageAccountResourceID,
    [System.String]$OutDir = '.\la-export',
    [System.Boolean]$RemoveLALogs = $false,
    [System.String]$DeleteAPIVersion = '2023-09-01',
    [System.Boolean]$AsRunbook = $false
)
### START: CONNECT TO AZURE ###
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.OperationalInsights',
    'Az.Resources',
    'Az.Storage'
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

# Ensures you do not inherit an AzContext in your runbook
Write-Verbose -Message 'Disabling Azure context autosave.'
Disable-AzContextAutosave -Scope Process

[System.Collections.ArrayList]$LAWRIDArray = $LAWResourceID.Split('/')

[System.String]$LASubscriptionID = $LAWRIDArray[2]
[System.String]$LAResourceGroupName = $LAWRIDArray[4]
[System.String]$LAWorkspaceName = $LAWRIDArray[-1]

# Connect to Azure with system-assigned managed identity
[System.String]$FirstAzTenantID = $EntraTenantID
[System.String]$FirstAzSubscriptionID = $LASubscriptionID

if ($true -eq $AsRunbook) {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-Verbose -Message $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}
else {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using user credentials to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-Verbose -Message $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}
### END: CONNECT TO AZURE ###
### START: READ FROM LAW ###
Write-Verbose -Message "Getting Workspace in resource group: '$LAResourceGroupName' with name: '$LAWorkspaceName'."
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAResourceGroupName -Name $LAWorkspaceName -ErrorAction SilentlyContinue

[System.Collections.ArrayList]$StorageAccountRIDArray = $StorageAccountResourceID.Split('/')

[System.String]$StorageAccountResourceGroupName = $StorageAccountRIDArray[4]
[System.String]$StorageAccountName = $StorageAccountRIDArray[-1]

Write-Verbose -Message "Getting storage account: '$StorageAccountName'."
$GetAzStorageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue

if ($GetWorkspace) {
    Write-Verbose -Message "Found Log Analytics Workspace in resource group: '$LAResourceGroupName' with name: '$LAWorkspaceName'."
}
else {
    Write-Error -Message "Did not find Log Analytics Workspace in resource group: '$LAResourceGroupName' with name: '$LAWorkspaceName'."
    throw
}

if ($GetAzStorageAccount) {
    Write-Verbose -Message "Found Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
}
else {
    Write-Error -Message "Did not find Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
    throw
}

# Loop in fixed windows
[System.Boolean]$FoundLogs = $false

Write-Verbose -Message 'Found workspace. Creating output directory.'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

[System.DateTime]$FromDateTimeUTCDateTime = $FromDateTimeUTC
[System.DateTime]$ToDateTimeUTCDateTime = $ToDateTimeUTC


if ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    Write-Verbose -Message "To date time: '$ToDateTimeUTC' is greater than from date time: '$FromDateTimeUTC'. Entering main query loop."
}
else {
    Write-Warning -Message "To date time: '$ToDateTimeUTC' is not greater than from date time: '$FromDateTimeUTC'. Not querying."
}

while ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    $NextTimeBlock = [datetime]::SpecifyKind($FromDateTimeUTCDateTime.AddMinutes($SliceMinutes), 'Utc')
    if ($NextTimeBlock -gt $ToDateTimeUTCDateTime) {
        $NextTimeBlock = $ToDateTimeUTCDateTime
    }

    $fileStamp = '{0:yyyyMMddHHmmss}-{1:yyyyMMddHHmmss}' -f $FromDateTimeUTCDateTime, $NextTimeBlock
    $outFile   = Join-Path $OutDir "$LATableName-$fileStamp.jsonl"

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')
    $KQLQuery = @"
$LATableName
| where TimeGenerated between (datetime($FromDateTimeUTCDateTimeStringLowercase) .. datetime($NextTimeBlockStringLowercase))
| order by TimeGenerated asc
"@
    #Write-Verbose -Message 'Query to run:'
    #Write-Verbose -Message $KQLQuery
    Write-Verbose -Message "Querying for logs between: '$FromDateTimeUTCDateTimeStringLowercase' and: '$NextTimeBlockStringLowercase'."
    [System.Collections.ArrayList]$ResponseArray = @()
    try {
        $ErrorActionPreference = 'Stop'
        $InvokeQuery = Invoke-AzOperationalInsightsQuery -Workspace $GetWorkspace -Query $KQLQuery -Wait 30 -ErrorAction SilentlyContinue
        if ($InvokeQuery) {
            $InvokeQueryResults = $InvokeQuery.Results
            $InvokeQueryResults | ForEach-Object -Process {
                $ResponseArray.Add($_) | Out-Null
            }
        }
    }
    catch {
        $_
        Write-Error -Message 'An error ocurred while executing the query.'
        throw
    }
    #$resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $KQLQuery

    # Write JSON Lines (one row per line). Keep depth high for dynamic columns.
    [System.Int32]$i = 1
    [System.Int32]$QueryCount = $ResponseArray.Count
    if (0 -lt $QueryCount) {
        [System.Boolean]$FoundLogs = $true
        Write-Verbose -Message "Found: '$QueryCount' results. Processing results for export."
        foreach ($Response in $ResponseArray) {
            #Write-Verbose -Message "Exporting result: '$i' of: '$QueryCount' results."
            ($Response | ConvertTo-Json -Depth 50 -Compress) | Out-File -FilePath $outFile -Append -Encoding utf8
            $i++
        }
        Write-Verbose -Message "Exported slice $FromDateTimeUTCDateTime -> $NextTimeBlock to $outFile"
    }
    $FromDateTimeUTCDateTime = $NextTimeBlock
}
Write-Verbose -Message 'Done querying. Moving on to export.'
### END: READ FROM LAW ###
### START: STORE IN BLOB ###
if ($true -eq $FoundLogs) {
    Write-Verbose -Message 'Logs were found. Creating container name.'
    $ctx = $GetAzStorageAccount.Context
    [System.DateTime]$FromDateTimeUTCDateTime = $FromDateTimeUTC
    [System.String]$ToDateTimeUTCDateTime = $ToDateTimeUTC
    [System.String]$FromDateTimeUTCFormatted = Get-Date -Date $FromDateTimeUTCDateTime -Format 'yyyy-MM-ddTHH-mm-ss'
    [System.String]$ToDateTimeUTCFormatted = Get-Date -Date $ToDateTimeUTCDateTime -Format 'yyyy-MM-ddTHH-mm-ss'
    [System.String]$ContainerName = ([System.String]::Concat($LATableName, '-', $FromDateTimeUTCFormatted, '-to-', $ToDateTimeUTCFormatted)).ToLower()
    Write-Verbose -Message "Container will be named: '$ContainerName' for this run."
    if (Get-AzStorageContainer -Name $ContainerName -Context $ctx -ErrorAction SilentlyContinue) {
        Write-Verbose -Message 'Found a container with the same name. Reusing.'
    }
    else {
        Write-Verbose -Message 'Container does not exist. Attempting to create it.'
        try {
            $ErrorActionPreference = 'Stop'
            $VerbosePreference = 'SilentlyContinue'
            New-AzStorageContainer -Name $ContainerName -Context $ctx -ErrorAction SilentlyContinue | Out-Null
            $VerbosePreference = 'Continue'
        }
        catch {
            $_
            Write-Error -Message "An error occurred while trying to create container: '$ContainerName'."
        }
        Write-Verbose -Message 'Container created.'
    }

    Write-Verbose -Message "Getting child items in: '$OutDir'."

    Get-ChildItem -Path $OutDir -Filter *.jsonl | ForEach-Object {
        [System.String]$BlobName = $_.Name
        Write-Verbose -Message "Uploading: '$BlobName'"
        try {
            $ErrorActionPreference = 'Stop'
            $VerbosePreference = 'SilentlyContinue'
            Set-AzStorageBlobContent -Context $ctx -Container $ContainerName -File $_.FullName -Blob $BlobName -Force | Out-Null
            $VerbosePreference = 'Continue'

        }
        catch {
            $_
            Write-Error -Message "An error occurred while uploading: '$BlobName' to blob storage."
            throw
        }
    }
    Write-Verbose -Message 'Done uploading logs.'
}
else {
    Write-Warning -Message 'No log messages found, so not storing data in Azure Storage.'
}
### END: STORE IN BLOB ###
### START: DELETE FROM LA ###
if ($true -eq $FoundLogs) {
    if ($true -eq $RemoveLALogs) {
        Write-Warning -Message "Will remove Log Analytics logs from table: '$LATableName' between: '$FromDateTimeUTC' and: '$ToDateTimeUTC'."
        [System.DateTime]$DeleteAPIStartTime = $FromDateTimeUTC
        [System.DateTime]$DeleteAPIEndTime = $ToDateTimeUTC
        [System.String]$DeleteAPIStartTimeFormatted = Get-Date -Date $DeleteAPIStartTime -Format 'yyyy-MM-ddTHH:mm:ss'
        [System.String]$DeleteAPIEndTimeFormatted = Get-Date -Date $DeleteAPIEndTime -Format 'yyyy-MM-ddTHH:mm:ss'
        [System.String]$DeleteAPIURI = [System.String]::Concat('https://management.azure.com/subscriptions/',$LASubscriptionID,'/resourceGroups/', $LAResourceGroupName, '/providers/microsoft.OperationalInsights/workspaces/', $LAWorkspaceName, '/tables/',$LATableName,'/deleteData?api-version=',$DeleteAPIVersion)

        $DeleteAPIBody = @{
            filters = @(
                @{
                    column   = 'TimeGenerated'
                    operator = '>'
                    value    = $DeleteAPIStartTimeFormatted
                },
                @{
                    column   = 'TimeGenerated'
                    operator = '<'
                    value    = $DeleteAPIEndTimeFormatted
                }
            )
        } | ConvertTo-Json -Depth 3

        # Make the POST request
        $Response = Invoke-AzRestMethod -Uri $DeleteAPIURI -Method POST -Payload $DeleteAPIBody
        #$response = Invoke-WebRequest -Uri $DeleteAPIBody -Method Post -Headers $headers -Body $DeleteAPIURI

        # Check for operation status URL in headers
        $operationId = $response.Headers['Azure-AsyncOperation']
        if (-not $operationId) {
            $operationId = $response.Headers['Location']
        }

        if ($operationId) {
            $operationUrl = $operationId[0]  # Take first value
            Write-Verbose -Message "Polling operation status at: $operationUrl"

            while ($true) {
                $statusResponse = Invoke-RestMethod -Uri $operationUrl -Headers $headers -Method Get
                Write-Verbose -Message "Status: $($statusResponse.status)"
                if ($statusResponse.status -eq 'Succeeded' -or $statusResponse.status -eq 'Failed') {
                    Write-Verbose -Message "Final status: $($statusResponse.status)"
                    break
                }
                Start-Sleep -Seconds 30 # Check status every 30 seconds
            }
        }
        else {
            Write-Verbose -Message 'No operation tracking URL found. Response body:'
            $response.Content
        }
    }
    else {
        Write-Verbose -Message 'Logs were found, but script was set to not delete any logs from Log Analytics. Moving on.'
    }
}
else {
    Write-Warning -Message 'No log messages found, so not removing logs, if enabled.'
}
Write-Verbose -Message 'Exiting!'
### END: DELETE FROM LA ###