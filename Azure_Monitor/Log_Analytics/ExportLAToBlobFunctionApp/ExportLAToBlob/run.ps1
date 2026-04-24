using namespace System.Net
[CmdletBinding(
    ConfirmImpact = 'Low',
    PositionalBinding = $false,
    SupportsPaging = $false,
    SupportsShouldProcess = $false
)]

# Input bindings are passed in via param block.
param(
    [Parameter(
        Mandatory = $true,
        ValueFromPipeline = $false,
        ValueFromPipelineByPropertyName = $false,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'The request body of the message.'
    )]
    [HttpRequestContext]$Request,
    $TriggerMetadata
)
### START: FUNCTIONS ###
Write-Information -MessageData 'Loading functions...'
function Write-ToLog {
    param (
        [ValidateSet(
            'Debug',
            'Error',
            'Information',
            'Progress',
            'Success',
            'Verbose',
            'Warning',
            IgnoreCase = $true
        )]
        [psobject]$Stream = 'Information',
        [ValidateNotNullOrEmpty()]
        [System.String]$MessageData
    )

    switch ($Stream) {
        'Debug' {
            Write-Debug -Message $MessageData
        }
        'Error' {
            Write-Error -Message $MessageData
        }
        'Information' {
            $InformationPreference = 'Continue'
            Write-Information -MessageData $MessageData
        }
        'Progress' {
            Write-Progress -Activity $MessageData
        }
        'Success' {
            Write-Output -InputObject $MessageData
        }
        'Warning' {
            Write-Warning -Message $MessageData
        }
        'Verbose' {
            Write-Verbose -Message $MessageData
        }
    }
}

Write-ToLog -Stream 'Information' -MessageData 'Finished loading functions.'
### END: FUNCTIONS ###
### START: DERIVE VARIABLES FROM REQUEST PARAMETER ###
Write-ToLog -Stream 'Information' -MessageData 'Deriving variables from request parameters...'
# Entra Tenant ID
[System.String]$EntraTenantID = $Request.Query.EntraTenantID
if (-not $EntraTenantID) {
    [System.String]$EntraTenantID = $Request.Body.EntraTenantID
}

if ($EntraTenantID -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'Entra Tenant ID was not provided in the query parameters or the request body. Please provide a valid Entra Tenant ID and try again.'
    throw 'Entra Tenant ID is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "Entra Tenant ID: '$EntraTenantID'."
}

# Log Analytics Resource ID
[System.String]$LAWResourceID = $Request.Query.LAWResourceID
if (-not $LAWResourceID) {
    [System.String]$LAWResourceID = $Request.Body.LAWResourceID
}

if ($LAWResourceID -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'Log Analytics Resource ID was not provided in the query parameters or the request body. Please provide a valid Log Analytics Resource ID and try again.'
    throw 'Log Analytics Resource ID is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "Log Analytics Resource ID: '$LAWResourceID'."
}

# Log Analytics Workspace Table Name
[System.String]$LAWTableName = $Request.Query.LAWTableName
if (-not $LAWTableName) {
    [System.String]$LAWTableName = $Request.Body.LAWTableName
}

if ($LAWTableName -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'Log Analytics Workspace Table Name was not provided in the query parameters or the request body. Please provide a valid Log Analytics Workspace Table Name and try again.'
    throw 'Log Analytics Workspace Table Name is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "Log Analytics Workspace Table Name: '$LAWTableName'."
}

# From Date Time in UTC
[System.String]$FromDateTimeUTC = $Request.Query.FromDateTimeUTC
if (-not $FromDateTimeUTC) {
    [System.String]$FromDateTimeUTC = $Request.Body.FromDateTimeUTC
}

if ($FromDateTimeUTC -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'From Date Time in UTC was not provided in the query parameters or the request body. Please provide a valid From Date Time in UTC and try again.'
    throw 'From Date Time in UTC is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "From Date Time in UTC: '$FromDateTimeUTC'."
}

# To Date Time in UTC
[System.String]$ToDateTimeUTC = $Request.Query.ToDateTimeUTC
if (-not $ToDateTimeUTC) {
    [System.String]$ToDateTimeUTC = $Request.Body.ToDateTimeUTC
}

if ($ToDateTimeUTC -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'To Date Time in UTC was not provided in the query parameters or the request body. Please provide a valid To Date Time in UTC and try again.'
    throw 'To Date Time in UTC is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "To Date Time in UTC: '$ToDateTimeUTC'."
}

# Is this a Search Job run?
[System.Boolean]$IsSearchJob = [System.Convert]::ToBoolean($Request.Query.IsSearchJob)
if (-not $IsSearchJob) {
    [System.Boolean]$IsSearchJob = [System.Convert]::ToBoolean($Request.Body.IsSearchJob)
}
else {
    [System.Boolean]$IsSearchJob = $false
}

Write-ToLog -Stream 'Information' -MessageData "Is Search Job: '$IsSearchJob'."

# Slice Minutes (bite size, like Pizza King)
[System.Int32]$SliceMinutes = [System.Convert]::ToInt32($Request.Query.SliceMinutes)
if ((-not $SliceMinutes) -or ($SliceMinutes -le 0)) {
    [System.Int32]$SliceMinutes = 15
    Write-ToLog -Stream Warning -MessageData "Slice Minutes was not provided or is less than or equal to 0 in the query parameters. Defaulting to: '$SliceMinutes' minutes."
}
else {
    [System.Int32]$SliceMinutes = [System.Convert]::ToInt32($Request.Body.SliceMinutes)
}

Write-ToLog -Stream 'Information' -MessageData "Slice Minutes: '$SliceMinutes'."

# Storage Account Resource ID
[System.String]$StorageAccountResourceID = $Request.Query.StorageAccountResourceID
if (-not $StorageAccountResourceID) {
    [System.String]$StorageAccountResourceID = $Request.Body.StorageAccountResourceID
}

if ($StorageAccountResourceID -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'Storage Account Resource ID was not provided in the query parameters or the request body. Please provide a valid Storage Account Resource ID and try again.'
    throw 'Storage Account Resource ID is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "Storage Account Resource ID: '$StorageAccountResourceID'."
}

# Storage Account Container Name
[System.String]$StorageAccountContainerName = $Request.Query.StorageAccountContainerName
if (-not $StorageAccountContainerName) {
    [System.String]$StorageAccountContainerName = $Request.Body.StorageAccountContainerName
}

if ($StorageAccountContainerName -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'Storage Account Container Name was not provided in the query parameters or the request body. Please provide a valid Storage Account Container Name and try again.'
    throw 'Storage Account Container Name is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "Storage Account Container Name: '$StorageAccountContainerName'."
}

# Log Output local directory (within the Function App)
[System.String]$OutDir = $Request.Query.OutDir
if (-not $OutDir) {
    [System.String]$OutDir = $Request.Body.OutDir
}
elseif ($OutDir.Length -lt 1) {
    [System.String]$OutDir = '.\la-export'
}
else {
    [System.String]$OutDir = '.\la-export'
}

if ($OutDir -in @('', $null)) {
    [System.String]$OutDir = '.\la-export'
    Write-ToLog -Stream Warning -MessageData "Output directory was not provided in the query parameters or the request body. Defaulting to: '$OutDir'."
}
else {
    [System.String]$OutDir = $Request.Body.OutDir
}

Write-ToLog -Stream 'Information' -MessageData "Temp. JSONL output directory within Function App: '$OutDir'."

# Remove the exported logs from Log Analytics (careful with this)
[System.Boolean]$RemoveLALogs = [System.Convert]::ToBoolean($Request.Query.RemoveLALogs)
if (-not $RemoveLALogs) {
    [System.Boolean]$RemoveLALogs = [System.Convert]::ToBoolean($Request.Body.RemoveLALogs)
}
else {
    [System.Boolean]$RemoveLALogs = $false
}

Write-ToLog -Stream 'Information' -MessageData "Remove logs from Log Analytics after export: '$RemoveLALogs'."

# The API Version of the Delete API used to remove the exported logs from Log Analytics
[System.String]$DeleteAPIVersion = $Request.Query.DeleteAPIVersion
if (-not $DeleteAPIVersion) {
    [System.String]$DeleteAPIVersion = $Request.Body.DeleteAPIVersion
}
elseif ($DeleteAPIVersion.Length -lt 9) {
    [System.String]$DeleteAPIVersion = '2023-09-01'
}
else {
    [System.String]$DeleteAPIVersion = '2023-09-01'
}

Write-ToLog -Stream 'Information' -MessageData "Delete API Version: '$DeleteAPIVersion'."

[System.Collections.ArrayList]$LAWRIDArray = $LAWResourceID.Split('/')

[System.String]$LAWSubscriptionID = $LAWRIDArray[2]
[System.String]$LAWResourceGroupName = $LAWRIDArray[4]
[System.String]$LAWorkspaceName = $LAWRIDArray[-1]

[System.String]$FirstAzTenantID = $EntraTenantID
[System.String]$FirstAzSubscriptionID = $LAWSubscriptionID
Write-ToLog -Stream 'Information' -MessageData 'Done deriving variables from request parameters.'

### END: DERIVE VARIABLES FROM REQUEST PARAMETER ###
### START: SETUP & MODULE IMPORT ###
$InformationPreference = 'Continue'

[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.OperationalInsights',
    'Az.Resources',
    'Az.Storage'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-ToLog -Stream Information -MessageData 'Starting to import PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    Write-ToLog -Stream Information -MessageData "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    try {
        $ErrorActionPreference = 'Stop'
        Import-Module -Name $Module | Out-Null
    }
    catch {
        $_
        Write-ToLog -Stream Error -MessageData "An error occurred while importing module: '$Module'."
        throw
    }
    Write-ToLog -Stream Information -MessageData "Successfully imported module: '$Module'."
    $i++
}

Write-ToLog -Stream Information -MessageData 'Finished importing PowerShell modules.'
$VerbosePreference = 'Continue'
### END: SETUP & MODULE IMPORT ###
### START: CONNECT TO AZURE ###
# Ensures you do not inherit an AzContext in your runbook
Write-ToLog -Stream Information -MessageData 'Disabling Azure context autosave.'
Disable-AzContextAutosave -Scope Process

if ($true -eq $AsRunbook) {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-ToLog -Stream Information -MessageData $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
    }
    catch {
        Write-ToLog -Stream Error -MessageData $_
    }
}
else {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using user credentials to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-ToLog -Stream Information -MessageData $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -WarningAction SilentlyContinue
    }
    catch {
        Write-ToLog -Stream Error -MessageData $_
    }
}
### END: CONNECT TO AZURE ###
### START: READ FROM LAW ###
Write-ToLog -Stream Information -MessageData "Getting Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAWResourceGroupName -Name $LAWorkspaceName -ErrorAction SilentlyContinue

if ($GetWorkspace) {
    Write-ToLog -Stream Information -MessageData "Found Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
}
else {
    Write-ToLog -Stream Error -MessageData "Did not find Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
    throw
}

[System.Collections.ArrayList]$StorageAccountRIDArray = $StorageAccountResourceID.Split('/')

[System.String]$StorageAccountResourceGroupName = $StorageAccountRIDArray[4]
[System.String]$StorageAccountName = $StorageAccountRIDArray[-1]

Write-ToLog -Stream Information -MessageData "Getting storage account: '$StorageAccountName'."
$GetAzStorageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue

if ($GetAzStorageAccount) {
    Write-ToLog -Stream Information -MessageData "Found Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
}
else {
    Write-ToLog -Stream Error -MessageData "Did not find Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
    throw
}

Write-ToLog -Stream Information -MessageData 'Found workspace. Creating output directory.'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

[System.DateTime]$FromDateTimeUTCDateTime = $FromDateTimeUTC
[System.DateTime]$ToDateTimeUTCDateTime = $ToDateTimeUTC


if ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    Write-ToLog -Stream Information -MessageData "To date time: '$ToDateTimeUTC' is greater than from date time: '$FromDateTimeUTC'. Entering main query loop."
}
else {
    Write-ToLog -Stream Warning -MessageData "To date time: '$ToDateTimeUTC' is not greater than from date time: '$FromDateTimeUTC'. Not querying."
}

# Set these to false until proven true. This drive container creation and uploads.
[System.Boolean]$FoundLogs = $false
[System.Boolean]$LogsAlreadyUploaded = $false

if ($true -eq $IsSearchJob) {
    Write-ToLog -Stream Warning -MessageData 'Executing a search job for this run. This may lengthen overall runbook execution time.'

    [System.DateTime]$SearchJobStartDateTime = $FromDateTimeUTC
    [System.DateTime]$SearchJobEndDateTime = $ToDateTimeUTC
    [System.String]$SearchJobStartDateTimeString = Get-Date -Date $SearchJobStartDateTime -Format 'MM-dd-yyyy HH:mm:ss'
    [System.String]$SearchJobEndDateTimeString = Get-Date -Date $SearchJobEndDateTime -Format 'MM-dd-yyyy HH:mm:ss'
    [System.String]$SearchJobTableNameStartDate = Get-Date -Date $SearchJobStartDateTime -Format 'yyyyMMddHHmmss'
    [System.String]$SearchJobTableNameEndDate = Get-Date -Date $SearchJobEndDateTime -Format 'yyyyMMddHHmmss'

    # Restrict new table name to LA table naming restrictions
    [System.String]$SearchJobTableName = [System.String]::Concat($LAWTableName.Substring(10),'_',$SearchJobTableNameStartDate,'_',$SearchJobTableNameEndDate,'_SRCH')

    Write-ToLog -Stream Information -MessageData "Creating a search job table named: '$SearchJobTableName' for starting date time: '$FromDateTimeUTC' and ending: '$ToDateTimeUTC'."

    Write-ToLog -Stream Information -MessageData "Will try to create a new Search Job table named: '$SearchJobTableName'."
    try {
        $ErrorActionPreference = 'Stop'
        New-AzOperationalInsightsSearchTable -ResourceGroupName $LAWResourceGroupName -WorkspaceName $LAWorkspaceName -TableName $SearchJobTableName -SearchQuery $KQLQuery -StartSearchTime $SearchJobStartDateTimeString -EndSearchTime $SearchJobEndDateTimeString
    }
    catch {
        $_
        Write-ToLog -Stream Error -MessageData 'An error occurred while creating the Search Job table.'
        throw
    }

    # Set the table to query to the name of the search table.
    [System.String]$LAWTableName = $SearchJobTableName
    Write-ToLog -Stream Information -MessageData 'Table name to search is now search job table name.'

    Write-ToLog -Stream Information -MessageData 'Search job table creation request submitted.'

    # Wait to query until the table's available.
    [System.Boolean]$SearchJobTableCreated = $false
    [System.Int32]$SearchJobTimeoutSeconds = 86400
    [System.Int32]$CurrentSeconds = 0
    [System.Int32]$SleepSeconds = 10

    while ($false -eq $SearchJobTableCreated) {
        Write-ToLog -Stream Information -MessageData "Searching for search job table: '$SearchJobTableName'."
        $GetSearchTable = Get-AzOperationalInsightsTable -ResourceGroupName $LAWResourceGroupName -WorkspaceName $LAWorkspaceName -TableName $SearchJobTableName -ErrorAction SilentlyContinue

        if ($GetSearchTable) {
            [System.Boolean]$SearchJobTableCreated = $true
            Write-ToLog -Stream Information -MessageData 'Search job table is available!'
        }
        else {
            Write-ToLog -Stream Information -MessageData 'Search job table not yet available. Waiting 10 seconds.'
            [System.Int32]$CurrentSeconds = $CurrentSeconds + $SleepSeconds
            Start-Sleep -Seconds $SleepSeconds

            if ($CurrentSeconds -gt $SearchJobTimeoutSeconds) {
                Write-ToLog -Stream Error -MessageData "Search job timed out after: '$CurrentSeconds' seconds. Please try a smaller search and remember to remove table: '$SearchJobTableName' if it becomes available."
                throw
            }
        }
    }
}
else {
    Write-ToLog -Stream Information -MessageData "Not running a search job. Treating logs as if they're in hot tier in the LAW."
}

# Loop in fixed slices of time
while ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    $NextTimeBlock = [datetime]::SpecifyKind($FromDateTimeUTCDateTime.AddMinutes($SliceMinutes), 'Utc')
    if ($NextTimeBlock -gt $ToDateTimeUTCDateTime) {
        $NextTimeBlock = $ToDateTimeUTCDateTime
    }

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')

    Write-ToLog -Stream Information -MessageData "Querying for logs between: '$FromDateTimeUTCDateTimeStringLowercase' and: '$NextTimeBlockStringLowercase'."
    $KQLQuery = @"
$LAWTableName
| where TimeGenerated between (datetime($FromDateTimeUTCDateTimeStringLowercase) .. datetime($NextTimeBlockStringLowercase))
| order by TimeGenerated asc
"@

    [System.Collections.ArrayList]$ResponseArray = @()
    try {
        $ErrorActionPreference = 'Stop'
        # Not specifying a timeout, but know that the max. timeout as of April 2026 is 10 minutes:
        # https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/timeouts
        # Best to govern this by narrowing the timeslice parameter value to something lower to get quicker results.
        Write-ToLog -Stream Information -MessageData "KQL Query being executed: '$KQLQuery'."
        $InvokeQuery = Invoke-AzOperationalInsightsQuery -Workspace $GetWorkspace -Query $KQLQuery
        if ($InvokeQuery) {
            $InvokeQueryResults = $InvokeQuery.Results
            $InvokeQueryResults | ForEach-Object -Process {
                $ResponseArray.Add($_) | Out-Null
            }
        }
    }
    catch {
        $_
        Write-ToLog -Stream Error -MessageData 'An error ocurred while executing the query.'
        throw
    }
    #$resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $KQLQuery

    # Write JSON Lines (one row per line). Keep depth high for dynamic columns.
    [System.Int32]$i = 1
    [System.Int32]$QueryCount = $ResponseArray.Count
    if (0 -lt $QueryCount) {
        [System.Boolean]$FoundLogs = $true
        [System.String]$FileStamp = '{0:yyyyMMddHHmmss}-{1:yyyyMMddHHmmss}' -f $FromDateTimeUTCDateTime, $NextTimeBlock
        [System.String]$OutFile   = Join-Path $OutDir "$LATableName-$FileStamp.jsonl"

        Write-ToLog -Stream Information -MessageData "Found: '$QueryCount' results. Writing out file: '$OutFile' and appending."

        [System.Collections.ArrayList]$OutFileArray = @()
        foreach ($Response in $ResponseArray) {
            #Write-ToLog -Stream Information -MessageData "Exporting result: '$i' of: '$QueryCount' results."
            ($Response | ConvertTo-Json -Depth 50 -Compress) | Out-File -FilePath $OutFile -Append -Encoding utf8
            $i++
        }
        Write-ToLog -Stream Information -MessageData "Exported slice $FromDateTimeUTCDateTime -> $NextTimeBlock to $OutFile"

        $OutFileArray.Add($OutFile) | Out-Null

        # Only create the container if it wasn't created already.
        $ctx = $GetAzStorageAccount.Context
        if ($false -eq $LogsAlreadyUploaded) {
            [System.Boolean]$LogsAlreadyUploaded = $true
            Write-ToLog -Stream Information -MessageData 'This is the first time logs have been found in this run. Testing for and creating storage container.'

            #Write-ToLog -Stream Information -MessageData 'Logs were found. Creating container name.'
            #[System.DateTime]$FromDateTimeUTCDateTime = $FromDateTimeUTC
            #[System.String]$ToDateTimeUTCDateTime = $ToDateTimeUTC
            #[System.String]$FromDateTimeUTCFormatted = Get-Date -Date $FromDateTimeUTCDateTime -Format 'yyyy-MM-ddTHH-mm-ss'
            #[System.String]$ToDateTimeUTCFormatted = Get-Date -Date $ToDateTimeUTCDateTime -Format 'yyyy-MM-ddTHH-mm-ss'
            #[System.String]$ContainerName = ([System.String]::Concat($LAWTableName, '-', $FromDateTimeUTCFormatted, '-to-', $ToDateTimeUTCFormatted)).ToLower()
            Write-ToLog -Stream Information -MessageData "Container will be named: '$StorageAccountContainerName' for this run."
            if (Get-AzStorageContainer -Name $StorageAccountContainerName -Context $ctx -ErrorAction SilentlyContinue) {
                Write-ToLog -Stream Information -MessageData 'Found a container with the same name. Reusing.'
            }
            else {
                Write-ToLog -Stream Information -MessageData 'Container does not exist. Attempting to create it.'
                try {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference = 'SilentlyContinue'
                    New-AzStorageContainer -Name $StorageAccountContainerName -Context $ctx -ErrorAction SilentlyContinue | Out-Null
                    $VerbosePreference = 'Continue'
                }
                catch {
                    $_
                    Write-ToLog -Stream Error -MessageData "An error occurred while trying to create container: '$StorageAccountContainerName'."
                }
                Write-ToLog -Stream Information -MessageData 'Container created.'
            }
        }

        # Upload logs founs
        Write-ToLog -Stream Information -MessageData 'Trying to upload logs for this time slice.'
        foreach ($OutFile in $OutFileArray) {
            Write-ToLog -Stream Information -MessageData "Getting item: '$OutFile' in: '$OutDir'."
            $GetOutFile = Get-Item -Path $OutFile
            [System.String]$OutFileBlobName = $GetOutFile.Name
            [System.String]$OutFileFullname = $GetOutFile.FullName

            # Upload logs if blob doesn't already exist. If it does, bail.
            Write-ToLog -Stream Information -MessageData 'Testing if blob already exists.'
            $VerbosePreference = 'SilentlyContinue'
            $GetBlob = Get-AzStorageBlobContent -Context $ctx -Container $StorageAccountContainerName -Blob $OutFileBlobName -ErrorAction SilentlyContinue -Verbose:$false
            $VerbosePreference = 'Continue'

            if ($GetBlob) {
                Write-ToLog -Stream Error -MessageData "ERROR: Blob: '$OutFileBlobName' already exists. Not uploading! Bailing."
                throw
            }
            else {
                Write-ToLog -Stream Information -MessageData "Attempting to upload file: '$OutFileFullname' as blob named: '$OutFileBlobName'"
                try {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference = 'SilentlyContinue'
                    Set-AzStorageBlobContent -Context $ctx -Container $StorageAccountContainerName -File $OutFileFullname -Blob $OutFileBlobName -Force -Verbose:$false | Out-Null
                    $VerbosePreference = 'Continue'

                }
                catch {
                    $_
                    Write-ToLog -Stream Error -MessageData "An error occurred while uploading: '$OutFileBlobName' to blob storage."
                    throw
                }
            }

        }
        Write-ToLog -Stream Information -MessageData 'Done uploading logs.'

        # Remove logs just uploaded
        Write-ToLog -Stream Information -MessageData 'Trying to remove the logs which were just uploaded.'
        foreach ($OutFile in $OutFileArray) {
            Write-ToLog -Stream Information -MessageData "Getting item: '$OutFile' in: '$OutDir'."
            $GetOutFile = Get-Item -Path $OutFile
            [System.String]$OutFileFullname = $GetOutFile.FullName

            try {
                $ErrorActionPreference = 'Stop'
                $VerbosePreference = 'SilentlyContinue'
                Write-ToLog -Stream Information -MessageData "Trying to remove: '$OutFileFullname'."
                Remove-Item -Path $OutFileFullname -Force | Out-Null
                $VerbosePreference = 'Continue'
            }
            catch {

            }
        }
        Write-ToLog -Stream Information -MessageData 'Done removing logs.'
    }
    $FromDateTimeUTCDateTime = $NextTimeBlock
}

Write-ToLog -Stream Information -MessageData 'Done querying. Moving on.'
### END: READ FROM LAW ###
### START: SEARCH JOB TABLE DELETION ###
if ($true -eq $IsSearchJob) {
    Write-ToLog -Stream Information -MessageData 'Search job was executed. Trying to remove table since querying is complete.'
    try {
        $ErrorActionPreference = 'Stop'
        [System.String]$TableDeleteString = [System.String]::Concat($LAWResourceID, '/tables/',$LAWTableName,'?api-version=2021-12-01-preview')
        Write-ToLog -Stream Information -MessageData "Table delete string: '$TableDeleteString'."

        Invoke-AzRestMethod -Path $TableDeleteString -Method DELETE -WaitForCompletion
    }
    catch {
        $_
        Write-ToLog -Stream Error -MessageData "An error occurred while trying to delete table: '$LAWTableName' using path: '$TableDeleteString'."
        throw
    }
}
### END: SEARCH JOB TABLE DELETION ###
### START: DELETE FROM LA ###
if ($true -eq $FoundLogs) {
    if ($true -eq $RemoveLALogs) {
        Write-ToLog -Stream Warning -MessageData "Will remove Log Analytics logs from table: '$LAWTableName' between: '$FromDateTimeUTC' and: '$ToDateTimeUTC'."
        [System.DateTime]$DeleteAPIStartTime = $FromDateTimeUTC
        [System.DateTime]$DeleteAPIEndTime = $ToDateTimeUTC
        [System.String]$DeleteAPIStartTimeFormatted = Get-Date -Date $DeleteAPIStartTime -Format 'yyyy-MM-ddTHH:mm:ss'
        [System.String]$DeleteAPIEndTimeFormatted = Get-Date -Date $DeleteAPIEndTime -Format 'yyyy-MM-ddTHH:mm:ss'
        [System.String]$DeleteAPIURI = [System.String]::Concat('https://management.azure.com/subscriptions/',$LAWSubscriptionID,'/resourceGroups/', $LAWResourceGroupName, '/providers/microsoft.OperationalInsights/workspaces/', $LAWorkspaceName, '/tables/',$LAWTableName,'/deleteData?api-version=',$DeleteAPIVersion)

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
            Write-ToLog -Stream Information -MessageData "Polling operation status at: $operationUrl"

            while ($true) {
                $statusResponse = Invoke-RestMethod -Uri $operationUrl -Headers $headers -Method Get
                Write-ToLog -Stream Information -MessageData "Status: $($statusResponse.status)"
                if ($statusResponse.status -eq 'Succeeded' -or $statusResponse.status -eq 'Failed') {
                    Write-ToLog -Stream Information -MessageData "Final status: $($statusResponse.status)"
                    break
                }
                Start-Sleep -Seconds 30 # Check status every 30 seconds
            }
        }
        else {
            Write-ToLog -Stream Information -MessageData 'No operation tracking URL found. Response body:'
            $response.Content
        }
    }
    else {
        Write-ToLog -Stream Information -MessageData 'Logs were found, but script was set to not delete any logs from Log Analytics. Moving on.'
    }
}
else {
    Write-ToLog -Stream Warning -MessageData 'No log messages found, so not removing logs, if enabled.'
}
### END: DELETE FROM LA ###

#### KEEP BELOW ####
[System.String]$BodyMessage = 'Exiting!'
Write-ToLog -Stream Information -MessageData $BodyMessage

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })
