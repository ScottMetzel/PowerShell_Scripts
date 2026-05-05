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
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'Continue'
Write-Verbose -Message 'Loading functions...'
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

Write-ToLog -Stream 'Verbose' -MessageData 'Finished loading functions.'
### END: FUNCTIONS ###
### START: DERIVE VARIABLES FROM REQUEST PARAMETER ###
Write-ToLog -Stream 'Verbose' -MessageData 'Deriving variables from request parameters...'

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

# Slice Seconds (bite size, like Pizza King)
[System.Int32]$SliceSeconds = $Request.Query.SliceSeconds
if ((-not $SliceSeconds) -or ($SliceSeconds -le 0)) {
    [System.Int32]$SliceSeconds = $Request.Body.SliceSeconds
}

if ((-not $SliceSeconds) -or ($SliceSeconds -le 0)) {
    [System.Int32]$SliceSeconds = 15
    Write-ToLog -Stream 'Warning' -MessageData "Slice Seconds was not provided or is less than or equal to 0 in the query parameters or the request body. Defaulting to: '$SliceSeconds' seconds."
}
Write-ToLog -Stream 'Information' -MessageData "Slice Seconds: '$SliceSeconds'."

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

# Parallelism through PowerShell
[System.Int32]$Parallelism = $Request.Query.Parallelism
if ((-not $Parallelism) -or ($Parallelism -le 0)) {
    [System.Int32]$Parallelism = $Request.Body.Parallelism
}

if ((-not $Parallelism) -or ($Parallelism -le 0)) {
    [System.Int32]$Parallelism = 5
    Write-ToLog -Stream 'Warning' -MessageData "Parallelism was not provided or is less than or equal to 0 in the query parameters or the request body. Defaulting to: '$Parallelism'."
}
Write-ToLog -Stream 'Information' -MessageData "Parallelism for this run is set to: '$Parallelism'."

# Log Output local directory name (within the Function App)
[System.String]$OutDirName = $Request.Query.OutDir
if (-not $OutDirName) {
    [System.String]$OutDirName = $Request.Body.OutDir
}
elseif ($OutDirName.Length -lt 1) {
    [System.String]$OutDirName = 'la-export'
}
else {
    [System.String]$OutDirName = 'la-export'
}

if ($OutDirName -in @('', $null)) {
    [System.String]$OutDirName = 'la-export'
    Write-ToLog -Stream 'Warning' -MessageData "Output directory name was not provided in the query parameters or the request body. Defaulting to: '$OutDirName'."
}
else {
    [System.String]$OutDirName = $Request.Body.OutDir
}

Write-ToLog -Stream 'Information' -MessageData "Temp. JSONL output directory name within Function App: '$OutDirName'."

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
if ((-not $DeleteAPIVersion) -or ($DeleteAPIVersion -in @('',$null))) {
    [System.String]$DeleteAPIVersion = $Request.Body.DeleteAPIVersion

    if ($DeleteAPIVersion -in @('',$null)) {
        [System.String]$DeleteAPIVersion = '2023-09-01'
    }
}
elseif (($DeleteAPIVersion.Length -lt 9) -or ($DeleteAPIVersion -in @('',$null))) {
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

Write-ToLog -Stream 'Verbose' -MessageData 'Done deriving variables from request parameters.'

### END: DERIVE VARIABLES FROM REQUEST PARAMETER ###
### START: CONNECT TO AZURE ###
# Ensures you do not inherit an AzContext in your runbook
Write-ToLog -Stream 'Verbose' -MessageData 'Setting Azure Subscription context.'
try {
    $ErrorActionPreference = 'Stop'
    Get-AzSubscription -SubscriptionId $LAWSubscriptionID | Set-AzContext -ErrorAction Stop
    Write-ToLog -Stream 'Information' -MessageData 'Context set.'
}
catch {
    $_
    Write-ToLog -Stream 'Error' -MessageData "An error occurred while setting Azure subscription context to Subscription ID: '$LAWSubscriptionID'."
    throw
}
### END: CONNECT TO AZURE ###
### START: READ FROM LAW ###
Write-ToLog -Stream 'Verbose' -MessageData "Getting Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAWResourceGroupName -Name $LAWorkspaceName -ErrorAction SilentlyContinue

if ($GetWorkspace) {
    Write-ToLog -Stream 'Information' -MessageData "Found Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
}
else {
    Write-ToLog -Stream 'Error' -MessageData "Did not find Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
    throw
}

[System.Collections.ArrayList]$StorageAccountRIDArray = $StorageAccountResourceID.Split('/')

[System.String]$StorageAccountResourceGroupName = $StorageAccountRIDArray[4]
[System.String]$StorageAccountName = $StorageAccountRIDArray[-1]

Write-ToLog -Stream 'Verbose' -MessageData "Getting storage account: '$StorageAccountName'."
$GetAzStorageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue

if ($GetAzStorageAccount) {
    Write-ToLog -Stream 'Information' -MessageData "Found Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
    # Create storage account context for use with blob operations later
    $ctx = $GetAzStorageAccount.Context
}
else {
    Write-ToLog -Stream 'Error' -MessageData "Did not find Storage Account in resource group: '$StorageAccountResourceGroupName' with name: '$StorageAccountName'."
    throw
}

[System.DateTime]$FromDateTimeUTCDateTime = [datetime]::SpecifyKind($FromDateTimeUTC, 'Utc')
[System.DateTime]$ToDateTimeUTCDateTime = [datetime]::SpecifyKind($ToDateTimeUTC, 'Utc')
if ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    Write-ToLog -Stream 'Verbose' -MessageData "To date time: '$ToDateTimeUTC' is greater than from date time: '$FromDateTimeUTC'. Entering main query loop."
}
else {
    Write-ToLog -Stream 'Warning' -MessageData "To date time: '$ToDateTimeUTC' is not greater than from date time: '$FromDateTimeUTC'. Not querying."
}

if ($true -eq $IsSearchJob) {
    Write-ToLog -Stream 'Warning' -MessageData 'Configuring run to query against a search job table.'

    [System.DateTime]$SearchJobStartDateTime = $FromDateTimeUTCDateTime
    [System.DateTime]$SearchJobEndDateTime = $ToDateTimeUTCDateTime
    [System.String]$SearchJobTableNameStartDate = Get-Date -Date $SearchJobStartDateTime -UFormat '%y%m%d'
    [System.String]$SearchJobTableNameEndDate = Get-Date -Date $SearchJobEndDateTime -UFormat '%y%m%d'

    # Restrict new table name to LA table naming restrictions
    # SecurityEvent_2604_2604_SRCH
    [System.String]$SearchJobTableName = [System.String]::Concat($LAWTableName,'_',$SearchJobTableNameStartDate,'_',$SearchJobTableNameEndDate,'_SRCH')

    # Set the table to query to the name of the search table.
    [System.String]$LAWTableName = $SearchJobTableName
    Write-ToLog -Stream 'Verbose' -MessageData "Table name to search is now search job table name: '$SearchJobTableName'."
}
else {
    Write-ToLog -Stream 'Verbose' -MessageData "Not running a search job. Treating logs as if they're in hot tier in the LAW."
}
### START: CREATE TEMPORARY OUTPUT DIRECTORY ###
[System.String]$OutDirFullPath = Join-Path -Path 'D:\Local' -ChildPath $OutDirName
Write-ToLog -Stream 'Verbose' -MessageData "Testing for temporary output directory: '$OutDirFullPath'."
if (-not (Test-Path -Path $OutDirFullPath)) {
    Write-ToLog -Stream 'Verbose' -MessageData "Temporary output directory: '$OutDirFullPath' does not exist. Attempting to create it."
    try {
        $ErrorActionPreference = 'Stop'
        New-Item -ItemType Directory -Path $OutDirFullPath -Force | Out-Null
        Write-ToLog -Stream 'Information' -MessageData "Temporary output directory: '$OutDirFullPath' created successfully."
    }
    catch {
        $_
        Write-ToLog -Stream 'Error' -MessageData "An error occurred while trying to create temporary output directory: '$OutDirFullPath'."
        throw
    }
}
else {
    Write-ToLog -Stream 'Verbose' -MessageData "Temporary output directory: '$OutDirFullPath' exists. Reusing."
}

Write-ToLog -Stream 'Verbose' -MessageData "Container will be named: '$StorageAccountContainerName' for this run."

### END: CREATE TEMPORARY OUTPUT DIRECTORY ###
### START: BUILD TIME WINDOWS ###
$DateTimeWindows = [ordered]@{}
Write-ToLog -Stream 'Information' -MessageData "Building time windows from: '$FromDateTimeUTCDateTime' to: '$ToDateTimeUTCDateTime' with slice interval of '$SliceSeconds' seconds."
while ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    $NextTimeBlock = [datetime]::SpecifyKind($FromDateTimeUTCDateTime.AddSeconds($SliceSeconds), 'Utc')
    if ($NextTimeBlock -gt $ToDateTimeUTCDateTime) {
        $NextTimeBlock = $ToDateTimeUTCDateTime
    }

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')

    $DateTimeWindows.Add($FromDateTimeUTCDateTime, $NextTimeBlock)
    $FromDateTimeUTCDateTime = $NextTimeBlock
}
Write-ToLog -Stream 'Information' -MessageData "Built '$($DateTimeWindows.Count)' time windows for processing. Performing log searches."
### END: BUILD TIME WINDOWS ###
### START: GET & EXPORT LOGS FROM LAW ###
# Trunction size refrence (seen below): https://learn.microsoft.com/en-us/kusto/concepts/query-limits?view=microsoft-fabric#limit-on-result-set-size-result-truncation
$DateTimeWindows.GetEnumerator() | ForEach-Object -ThrottleLimit $Parallelism -Parallel {
    ## Redefine Write-ToLog function inside parallel runspace
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
    ##
    $LAWTableName = $Using:LAWTableName
    $GetWorkspace = $Using:GetWorkspace
    $OutDirFullPath = $Using:OutDirFullPath
    $ctx = $Using:ctx
    $StorageAccountContainerName = $Using:StorageAccountContainerName
    $IsSearchJob = $Using:IsSearchJob

    [System.DateTime]$FromDateTimeUTCDateTime = $_.Key
    [System.DateTime]$NextTimeBlock = $_.Value

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')

    Write-ToLog -Stream 'Information' -MessageData "Querying for logs between: '$FromDateTimeUTCDateTimeStringLowercase' and: '$NextTimeBlockStringLowercase'."
    if ($true -eq $IsSearchJob) {
        Write-ToLog -Stream 'Information' -MessageData 'Setting KQL query to look for logs in a search job table.'
        $KQLQuery = @"
$LAWTableName
| where _OriginalTimeGenerated between (datetime($FromDateTimeUTCDateTimeStringLowercase) .. datetime($NextTimeBlockStringLowercase))
| order by _OriginalTimeGenerated asc
"@
    }
    else {
        Write-ToLog -Stream 'Information' -MessageData 'Setting KQL query to look for logs in a Log Analytics Plan table.'
        $KQLQuery = @"
$LAWTableName
| where TimeGenerated between (datetime($FromDateTimeUTCDateTimeStringLowercase) .. datetime($NextTimeBlockStringLowercase))
| order by TimeGenerated asc
"@
    }

    [System.Collections.ArrayList]$ResponseArray = @()
    try {
        $ErrorActionPreference = 'Stop'
        # Not specifying a timeout, but know that the max. timeout as of April 2026 is 10 minutes:
        # https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/timeouts
        # Best to govern this by narrowing the timeslice parameter value to something lower to get quicker results.
        Write-ToLog -Stream 'Information' -MessageData "KQL Query being executed: '$KQLQuery'."
        $InvokeQuery = Invoke-AzOperationalInsightsQuery -Workspace $GetWorkspace -Query $KQLQuery -ErrorAction SilentlyContinue
        if ($InvokeQuery) {
            Write-Verbose -Message 'Found results. Adding to response array.'
            $InvokeQueryResults = $InvokeQuery.Results
            $InvokeQueryResults | ForEach-Object -Process {
                $ResponseArray.Add($_) | Out-Null
            }
        }
        elseif ($InvokeQuery.Error -notin @('',$null)) {
            Write-ToLog -Stream 'Error' -MessageData 'Query result returned at least one error.'
        }
        else {
            Write-ToLog -Stream 'Information' -MessageData "No results for dates from: '$FromDateTimeUTCDateTimeStringLowercase' to: '$NextTimeBlockStringLowercase'."
        }
    }
    catch {
        $_
        Write-ToLog -Stream 'Error' -MessageData $InvokeQuery.Error
        throw
    }

    # Write JSON Lines (one row per line). Keep depth high for dynamic columns.
    [System.Int32]$i = 1
    [System.Int32]$QueryCount = $ResponseArray.Count
    if (0 -lt $QueryCount) {
        [System.String]$FileStamp = '{0:yyyyMMddHHmmss}-{1:yyyyMMddHHmmss}' -f $FromDateTimeUTCDateTime, $NextTimeBlock
        [System.String]$OutFileName = "$LAWTableName-$FileStamp.jsonl"
        [System.String]$OutFileFullPath   = Join-Path -Path $OutDirFullPath -ChildPath $OutFileName

        Write-ToLog -Stream 'Information' -MessageData "Found: '$QueryCount' results. Attempting to create temporary output file: '$OutFileFullPath'."
        try {
            $ErrorActionPreference = 'Stop'
            New-Item -ItemType File -Path $OutDirFullPath -Name $OutFileName -Force
            Write-ToLog -Stream 'Verbose' -MessageData "Temporary output file: '$OutFileFullPath' created successfully."
        }
        catch {
            $_
            Write-ToLog -Stream 'Error' -MessageData "An error occurred while trying to create temporary output file: '$OutFileFullPath'."
            throw
        }

        Write-ToLog -Stream 'Verbose' -MessageData "Writing out file: '$OutFileFullPath' and appending."
        [System.Collections.ArrayList]$OutFileArray = @()
        foreach ($Response in $ResponseArray) {
            #Write-ToLog -Stream 'Information' -MessageData "Exporting result: '$i' of: '$QueryCount' results."
            ($Response | ConvertTo-Json -Depth 50 -Compress) | Out-File -FilePath $OutFileFullPath -Append -Encoding utf8
            $i++
        }
        Write-ToLog -Stream 'Information' -MessageData "Exported slice $FromDateTimeUTCDateTime -> $NextTimeBlock to $OutFileFullPath"

        $OutFileArray.Add($OutFileFullPath) | Out-Null

        # Upload logs found in this time slice to blob storage
        Write-ToLog -Stream 'Information' -MessageData 'Trying to upload logs for this time slice.'
        foreach ($OutFile in $OutFileArray) {
            Write-ToLog -Stream 'Verbose' -MessageData "Getting item: '$OutFile' in: '$OutDirName'."
            $GetOutFile = Get-Item -Path $OutFile
            [System.String]$OutFileBlobName = $GetOutFile.Name
            [System.String]$OutFileFullname = $GetOutFile.FullName

            # Upload logs if blob doesn't already exist. If it does, bail.
            Write-ToLog -Stream 'Verbose' -MessageData 'Testing if blob already exists.'
            $GetBlob = Get-AzStorageBlobContent -Context $ctx -Container $StorageAccountContainerName -Blob $OutFileBlobName -ErrorAction SilentlyContinue -Verbose:$false

            if ($GetBlob) {
                Write-ToLog -Stream 'Error' -MessageData "ERROR: Blob: '$OutFileBlobName' already exists. Not uploading! Bailing."
                throw
            }
            else {
                Write-ToLog -Stream 'Verbose' -MessageData "Attempting to upload file: '$OutFileFullname' as blob named: '$OutFileBlobName'"
                try {
                    $ErrorActionPreference = 'Stop'
                    Set-AzStorageBlobContent -Context $ctx -Container $StorageAccountContainerName -File $OutFileFullname -Blob $OutFileBlobName -Force -Verbose:$false | Out-Null
                    Write-ToLog -Stream 'Information' -MessageData "Successfully uploaded file: '$OutFileFullname' as blob named: '$OutFileBlobName'."
                }
                catch {
                    $_
                    Write-ToLog -Stream 'Error' -MessageData "An error occurred while uploading: '$OutFileBlobName' to blob storage."
                    throw
                }
            }
        }
        # Remove logs just uploaded
        Write-ToLog -Stream 'Verbose' -MessageData 'Trying to remove the logs which were just uploaded.'
        foreach ($OutFile in $OutFileArray) {
            Write-ToLog -Stream 'Verbose' -MessageData "Getting item: '$OutFile' in: '$OutDirName'."
            $GetOutFile = Get-Item -Path $OutFile
            [System.String]$OutFileFullname = $GetOutFile.FullName

            try {
                $ErrorActionPreference = 'Stop'
                Write-ToLog -Stream 'Verbose' -MessageData "Trying to remove: '$OutFileFullname'."
                Remove-Item -Path $OutFileFullname -Force | Out-Null
                Write-ToLog -Stream 'Information' -MessageData "Successfully removed: '$OutFileFullname'."
            }
            catch {
                $_
                Write-ToLog -Stream 'Error' -MessageData "An error occurred while trying to remove: '$OutFileFullname'."
            }
        }
        Write-ToLog -Stream 'Verbose' -MessageData 'Done removing logs.'
    }
}

Write-ToLog -Stream 'Information' -MessageData 'Done querying. Moving on.'
### END: GET & EXPORT LOGS FROM LAW ###
#### Push output binding ####
[System.String]$BodyMessage = 'Exiting!'
Write-ToLog -Stream 'Information' -MessageData $BodyMessage

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })