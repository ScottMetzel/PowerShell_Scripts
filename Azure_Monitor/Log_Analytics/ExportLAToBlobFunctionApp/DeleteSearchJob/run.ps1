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

# Slice Minutes (bite size, like Pizza King)
[System.Int32]$SliceMinutes = $Request.Query.SliceMinutes
if ((-not $SliceMinutes) -or ($SliceMinutes -le 0)) {
    [System.Int32]$SliceMinutes = $Request.Body.SliceMinutes
}

if ((-not $SliceMinutes) -or ($SliceMinutes -le 0)) {
    [System.Int32]$SliceMinutes = 15
    Write-ToLog -Stream 'Warning' -MessageData "Slice Minutes was not provided or is less than or equal to 0 in the query parameters or the request body. Defaulting to: '$SliceMinutes' minutes."
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
### START: GET LAW & SET SEARCH JOB VARIABLES ###
Write-ToLog -Stream 'Verbose' -MessageData "Getting Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAWResourceGroupName -Name $LAWorkspaceName -ErrorAction SilentlyContinue

if ($GetWorkspace) {
    Write-ToLog -Stream 'Information' -MessageData "Found Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
}
else {
    Write-ToLog -Stream 'Error' -MessageData "Did not find Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
    throw
}

[System.DateTime]$FromDateTimeUTCDateTime = $FromDateTimeUTC
[System.DateTime]$ToDateTimeUTCDateTime = $ToDateTimeUTC
if ($FromDateTimeUTCDateTime -lt $ToDateTimeUTCDateTime) {
    Write-ToLog -Stream 'Verbose' -MessageData "To date time: '$ToDateTimeUTC' is greater than from date time: '$FromDateTimeUTC'. Entering main query loop."
}
else {
    Write-ToLog -Stream 'Warning' -MessageData "To date time: '$ToDateTimeUTC' is not greater than from date time: '$FromDateTimeUTC'. Not querying."
}

if ($true -eq $IsSearchJob) {
    Write-ToLog -Stream 'Warning' -MessageData 'Search job should have been executed in a prior run.'

    [System.DateTime]$SearchJobStartDateTime = $FromDateTimeUTC
    [System.DateTime]$SearchJobEndDateTime = $ToDateTimeUTC
    [System.String]$SearchJobTableNameStartDate = Get-Date -Date $SearchJobStartDateTime -Format 'yyyyMMddHHmmss'
    [System.String]$SearchJobTableNameEndDate = Get-Date -Date $SearchJobEndDateTime -Format 'yyyyMMddHHmmss'

    # Restrict new table name to LA table naming restrictions
    [System.String]$SearchJobTableName = [System.String]::Concat($LAWTableName,'_',$SearchJobTableNameStartDate,'_',$SearchJobTableNameEndDate,'_SRCH')

    # Set the table to query to the name of the search table.
    [System.String]$LAWTableName = $SearchJobTableName
    Write-ToLog -Stream 'Verbose' -MessageData 'Table name to search is now search job table name.'
}

### END: GET LAW & SET SEARCH JOB VARIABLES ###
### START: SEARCH JOB TABLE DELETION ###
if ($true -eq $IsSearchJob) {
    Write-ToLog -Stream 'Information' -MessageData 'Search job was executed. Trying to remove table since querying is complete.'
    try {
        $ErrorActionPreference = 'Stop'
        [System.String]$TableDeleteString = [System.String]::Concat($LAWResourceID, '/tables/',$LAWTableName,'?api-version=2021-12-01-preview')
        Write-ToLog -Stream 'Verbose' -MessageData "Table delete string: '$TableDeleteString'."

        Invoke-AzRestMethod -Path $TableDeleteString -Method DELETE -WaitForCompletion
    }
    catch {
        $_
        Write-ToLog -Stream 'Error' -MessageData "An error occurred while trying to delete table: '$LAWTableName' using path: '$TableDeleteString'."
        throw
    }
}
### END: SEARCH JOB TABLE DELETION ###

#### Push output binding ####
[System.String]$BodyMessage = 'Exiting!'
Write-ToLog -Stream 'Information' -MessageData $BodyMessage

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })