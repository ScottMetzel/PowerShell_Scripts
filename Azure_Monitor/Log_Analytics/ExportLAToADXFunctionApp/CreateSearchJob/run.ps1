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
### START: LOAD MODULES ###
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.Resources'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-ToLog -Stream 'Information' -MessageData 'Importing PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    Write-ToLog -Stream 'Verbose' -MessageData "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    Import-Module -Name $Module *> $null
    $i++
}
Write-ToLog -Stream 'Information' -MessageData 'Finished loading modules.'
### END: LOAD MODULES ###
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
    Get-AzSubscription -SubscriptionId $LAWSubscriptionID | Set-AzContext -ErrorAction Stop *> $null
    Write-ToLog -Stream 'Information' -MessageData 'Context set.'
}
catch {
    $_
    Write-ToLog -Stream 'Error' -MessageData "An error occurred while setting Azure subscription context to Subscription ID: '$LAWSubscriptionID'."
    throw
}
### END: CONNECT TO AZURE ###
### START: GET LAW & CREATE SEARCH JOB ###
Write-ToLog -Stream 'Verbose' -MessageData "Getting Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAWResourceGroupName -Name $LAWorkspaceName -ErrorAction SilentlyContinue

if ($GetWorkspace) {
    Write-ToLog -Stream 'Information' -MessageData "Found Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
}
else {
    Write-ToLog -Stream 'Error' -MessageData "Did not find Log Analytics Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
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
    Write-ToLog -Stream 'Warning' -MessageData 'Executing a search job for this run. This may lengthen overall runbook execution time.'

    [System.DateTime]$SearchJobStartDateTime = $FromDateTimeUTCDateTime
    [System.DateTime]$SearchJobEndDateTime = $ToDateTimeUTCDateTime
    [System.String]$SearchJobTableNameStartDate = Get-Date -Date $SearchJobStartDateTime -UFormat '%y%m%d'
    [System.String]$SearchJobTableNameEndDate = Get-Date -Date $SearchJobEndDateTime -UFormat '%y%m%d'

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$ToDateTimeUTCDateTimeStringLowercase = $ToDateTimeUTCDateTime.ToString('o')

    Write-ToLog -Stream 'Information' -MessageData "Querying for logs between: '$FromDateTimeUTCDateTimeStringLowercase' and: '$ToDateTimeUTCDateTimeStringLowercase'."
    $KQLQuery = @"
$LAWTableName
"@
    Write-ToLog -Stream 'Information' -MessageData "KQL Query to execute: '$KQLQuery'."

    # Restrict new table name to LA table naming restrictions
    [System.String]$SearchJobTableName = [System.String]::Concat($LAWTableName,'_',$SearchJobTableNameStartDate,'_',$SearchJobTableNameEndDate,'_SRCH')

    Write-ToLog -Stream 'Information' -MessageData "Creating search job table name is: '$SearchJobTableName'."

    [System.String]$TablesAPIVersion = '2025-07-01'
    [System.String]$CreateSearchTableURI = [System.String]::Concat('https://management.azure.com/subscriptions/',$LAWSubscriptionID,'/resourcegroups/',$LAWResourceGroupName,'/providers/Microsoft.OperationalInsights/workspaces/',$LAWorkspaceName,'/tables/',$SearchJobTableName,'?api-version=',$TablesAPIVersion)
    Write-ToLog -Stream 'Information' -MessageData "Create Search Table API URL is: '$CreateSearchTableURI'"

    Write-ToLog -Stream 'Information' -MessageData "Checking for search job table name: '$SearchJobTableName' to ensure it doesn't already exist before creating the search job."
    $GetSearchTable = Invoke-AzRestMethod -Uri $CreateSearchTableURI -Method GET -ErrorAction SilentlyContinue
    if ($GetSearchTable) {
        Write-ToLog -Stream 'Error' -MessageData "Search job table with name: '$SearchJobTableName' already exists. Please choose a different name for the search job table and try again."
        throw "Search job table with name: '$SearchJobTableName' already exists."
    }
    else {
        Write-ToLog -Stream 'Information' -MessageData "No existing search job table with name: '$SearchJobTableName' was found. Proceeding with search job creation."
    }

    $SearchTableAPIBody = [ordered]@{
        'properties' = @{
            'searchResults' = @{
                query           = $KQLQuery
                startSearchTime = $FromDateTimeUTCDateTime;
                endSearchTime   = $ToDateTimeUTCDateTime;
            }
        }
    }
    $SearchTableAPIBodyJSON = ConvertTo-Json -InputObject $SearchTableAPIBody -Depth 10
    <#
    {
    "properties": {
        "searchResults": {
                "query": "Syslog | where * has 'suspected.exe'",
                "limit": 1000,
                "startSearchTime": "2025-01-01T00:00:00Z",
                "endSearchTime": "2025-11-30T00:00:00Z"
            }
    }
}
    #>
    Write-ToLog -Stream 'Information' -MessageData "Creating search job for starting date time: '$FromDateTimeUTCDateTime' and ending: '$ToDateTimeUTCDateTime'."

    try {
        $ErrorActionPreference = 'Stop'
        $NewSearchTable = Invoke-AzRestMethod -Uri $CreateSearchTableURI -Method PUT -Payload $SearchTableAPIBodyJSON
        #New-AzOperationalInsightsSearchTable -ResourceGroupName $LAWResourceGroupName -WorkspaceName $LAWorkspaceName -TableName $SearchJobTableName -SearchQuery $KQLQuery -StartSearchTime $FromDateTimeUTCDateTime -EndSearchTime $SearchJobEndDateTime -RetentionInDays -1 -AsJob
        Write-ToLog -Stream 'Verbose' -MessageData 'Search job table creation request submitted.'
    }
    catch {
        $_
        Write-ToLog -Stream 'Error' -MessageData 'An error occurred while creating the Search Job table.'
        throw
    }
    [System.Int32]$NewSearchTableStatusCode = $NewSearchTable.StatusCode
    [System.Collections.ArrayList]$SearchTableStatusCodeArray = @()
    200..299 | ForEach-Object -Process {
        $SearchTableStatusCodeArray.Add($_) | Out-Null
    }

    $SearchTableStatusCodeArray.Add(400) # Add 400 to the array since if the search query is bad, the API will return a 400, but it still means the search job was created, just with a bad query. This allows us to differentiate between a failed search job creation and a search job creation with a bad query.

    if ($NewSearchTableStatusCode -in $SearchTableStatusCodeArray) {
        Write-ToLog -Stream 'Information' -MessageData "New search job request processing. Status code: '$NewSearchTableStatusCode'."
    }
    else {
        Write-ToLog -Stream 'Error' -MessageData "New search job request error code: '$NewSearchTableStatusCode'."
        throw
    }

    # Set the table to query to the name of the search table.
    [System.String]$LAWTableName = $SearchJobTableName
    Write-ToLog -Stream 'Verbose' -MessageData 'Table name to search is now search job table name.'

    # Wait to query until the table's available.
    [System.Boolean]$SearchJobTableCreated = $false
    [System.Int32]$SearchJobTimeoutSeconds = 86400
    [System.Int32]$CurrentSeconds = 0
    [System.Int32]$SleepSeconds = 10

    while ($false -eq $SearchJobTableCreated) {
        Write-ToLog -Stream 'Information' -MessageData "Searching for search job table: '$SearchJobTableName'."
        $GetSearchTable = Invoke-AzRestMethod -Uri $CreateSearchTableURI -Method GET
        $SearchTableContentTable = ConvertFrom-Json -InputObject $GetSearchTable.Content -AsHashtable -Depth 10
        #$GetSearchTable = Get-AzOperationalInsightsTable -ResourceGroupName $LAWResourceGroupName -WorkspaceName $LAWorkspaceName -TableName $SearchJobTableName -ErrorAction SilentlyContinue
        [System.String]$SearchTableProvisioningState = $SearchTableContentTable.properties.provisioningState
        if ('Succeeded' -eq $SearchTableProvisioningState) {
            [System.Boolean]$SearchJobTableCreated = $true
            Write-ToLog -Stream 'Information' -MessageData "Search job table is available! Status: '$SearchTableProvisioningState'"
        }
        elseif ($SearchTableProvisioningState -in @('Failed', 'Error')) {
            Write-ToLog -Stream 'Error' -MessageData "Creation of search job table failed. Status: '$SearchTableProvisioningState'"
            throw
        }
        else {
            Write-ToLog -Stream 'Information' -MessageData "Search job table not available yet. Status: '$SearchTableProvisioningState'. Waiting 10 seconds."
            [System.Int32]$CurrentSeconds = $CurrentSeconds + $SleepSeconds
            Start-Sleep -Seconds $SleepSeconds

            if ($CurrentSeconds -gt $SearchJobTimeoutSeconds) {
                Write-ToLog -Stream 'Error' -MessageData "Search job timed out after: '$CurrentSeconds' seconds. Please try a smaller search and remember to remove table: '$SearchJobTableName' if it becomes available."
                throw
            }
        }
    }
}
else {
    Write-ToLog -Stream 'Verbose' -MessageData "Not running a search job. Treating logs as if they're in hot tier in the LAW."
}
### END: GET LAW & CREATE SEARCH JOB ###

#### Push output binding ####
if ($IsSearchJob) {
    [System.String]$BodyMessage = "Created search job table named: '$SearchJobTableName'. Exiting."
}
else {
    [System.String]$BodyMessage = "Didn't create a search job table since IsSearchJob wasn't true."
}

Write-ToLog -Stream 'Information' -MessageData $BodyMessage

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })