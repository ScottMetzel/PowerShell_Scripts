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
    'Az.Accounts'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-ToLog -Stream 'Information' -MessageData 'Importing PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    Write-ToLog -Stream 'Verbose' -MessageData "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    $PreviousVerbosePreference = $VerbosePreference
    $PreviousInformationPreference = $InformationPreference
    $VerbosePreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    Import-Module -Name $Module -Verbose:$false *> $null
    $VerbosePreference = $PreviousVerbosePreference
    $InformationPreference = $PreviousInformationPreference
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

# ADX Cluster URI
[System.String]$ADXClusterURI = $Request.Query.ADXClusterURI
if (-not $ADXClusterURI) {
    [System.String]$ADXClusterURI = $Request.Body.ADXClusterURI
}

if ($ADXClusterURI -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'ADX Cluster URI was not provided in the query parameters or the request body. Please provide a valid ADX Cluster URI and try again.'
    throw 'ADX Cluster URI is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "ADX Cluster URI: '$ADXClusterURI'."
}

# ADX Database Name
[System.String]$ADXDatabaseName = $Request.Query.ADXDatabaseName
if (-not $ADXDatabaseName) {
    [System.String]$ADXDatabaseName = $Request.Body.ADXDatabaseName
}

if ($ADXDatabaseName -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'ADX Database Name was not provided in the query parameters or the request body. Please provide a valid ADX Database Name and try again.'
    throw 'ADX Database Name is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "ADX Database Name: '$ADXDatabaseName'."
}

# ADX Table Name
[System.String]$ADXTableName = $Request.Query.ADXTableName
if (-not $ADXTableName) {
    [System.String]$ADXTableName = $Request.Body.ADXTableName
}

if ($ADXTableName -in @('', $null)) {
    Write-ToLog -Stream 'Error' -MessageData 'ADX Table Name was not provided in the query parameters or the request body. Please provide a valid ADX Table Name and try again.'
    throw 'ADX Table Name is required.'
}
else {
    Write-ToLog -Stream 'Information' -MessageData "ADX Table Name: '$ADXTableName'."
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

# ADX Timeout Value (in minutes) for the .set-or-append command
[System.Int32]$ADXTimeoutMinutes = $Request.Query.ADXTimeoutMinutes
if ((-not $ADXTimeoutMinutes) -or ($ADXTimeoutMinutes -le 0)) {
    [System.Int32]$ADXTimeoutMinutes = $Request.Body.ADXTimeoutMinutes
}

if ((-not $ADXTimeoutMinutes) -or ($ADXTimeoutMinutes -le 0)) {
    [System.Int32]$ADXTimeoutMinutes = 10
    Write-ToLog -Stream 'Warning' -MessageData "ADX Timeout Minutes was not provided or is less than or equal to 0 in the query parameters or the request body. Defaulting to: '$ADXTimeoutMinutes'."
}
Write-ToLog -Stream 'Information' -MessageData "ADX Timeout Minutes for this run is set to: '$ADXTimeoutMinutes'."

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
### START: GET WORKSPACE & SET DATE TIME VARIABLES ###
Write-ToLog -Stream 'Verbose' -MessageData "Getting Workspace in resource group: '$LAWResourceGroupName' with name: '$LAWorkspaceName'."
# GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}?api-version=2025-07-01
$WorkspaceURI = [System.String]::Concat('https://management.azure.com/subscriptions/', $LAWSubscriptionID, '/resourceGroups/', $LAWResourceGroupName, '/providers/Microsoft.OperationalInsights/workspaces/', $LAWorkspaceName, '?api-version=2025-07-01')
$GetWorkspace = Invoke-AzRestMethod -Method GET -Uri $WorkspaceURI -ErrorAction SilentlyContinue

if (200 -eq $GetWorkspace.StatusCode) {
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
### END: GET WORKSPACE & SET DATE TIME VARIABLES ###
### START: IS SEARCH JOB? ###
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
### END: IS SEARCH JOB? ###
### START: DEFINE STATIC VARIABLES ###
# Reference Kusto Connection Strings: https://learn.microsoft.com/en-us/kusto/api/connection-strings/kusto?view=azure-data-explorer&preserve-view=true#authentication-properties-details
[System.String]$clusterUrl = [System.String]::Concat($ADXClusterURI, '/', $ADXDatabaseName)
$LAWClusterURI = [System.String]::Concat('https://ade.loganalytics.io/subscriptions/', $LAWSubscriptionID, '/resourcegroups/', $LAWResourceGroupName, '/providers/microsoft.operationalinsights/workspaces/', $LAWorkspaceName)
$LAWDBName = $LAWorkspaceName
### END: DEFINE STATIC VARIABLES ###
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

    $DateTimeWindows.Add($FromDateTimeUTCDateTimeStringLowercase, $NextTimeBlockStringLowercase)
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
    ### START: LOAD MODULES ###
    [System.Collections.ArrayList]$ModulesToImport = @(
        'Az.Accounts'
    )

    [System.Int32]$i = 1
    [System.Int32]$ModulesToImportCount = $ModulesToImport.Count

    Write-ToLog -Stream 'Verbose' -MessageData 'Importing PowerShell modules within runspace.'
    foreach ($Module in $ModulesToImport) {
        Write-ToLog -Stream 'Verbose' -MessageData "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
        $PreviousVerbosePreference = $VerbosePreference
        $PreviousInformationPreference = $InformationPreference
        $VerbosePreference = 'SilentlyContinue'
        $InformationPreference = 'SilentlyContinue'
        Import-Module -Name $Module -Verbose:$false *> $null
        $VerbosePreference = $PreviousVerbosePreference
        $InformationPreference = $PreviousInformationPreference
        $i++
    }
    Write-ToLog -Stream 'Verbose' -MessageData 'Finished loading modules.'
    ### END: LOAD MODULES ###
    ##
    $LAWTableName = $Using:LAWTableName
    $GetWorkspace = $Using:GetWorkspace
    $IsSearchJob = $Using:IsSearchJob
    $clusterUrl   = $Using:clusterUrl
    $ADXDatabaseName = $Using:ADXDatabaseName
    $ADXTableName = $Using:ADXTableName
    $LAWClusterURI = $Using:LAWClusterURI
    $LAWDBName = $Using:LAWDBName
    $SearchJobTableName = $Using:SearchJobTableName
    $ADXTimeoutMinutes = $Using:ADXTimeoutMinutes

    [System.DateTime]$FromDateTimeUTCDateTime = $_.Key
    [System.DateTime]$NextTimeBlock = $_.Value

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')

    # Load SDK — point to wherever you have Kusto.Data.dll
    [System.String]$KustoToolsPath = (Resolve-Path -Path '.\bin\microsoft.azure.kusto.tools.14.1.2\tools\net8.0').Path
    [System.String]$KustoToolsDataDllPath = [System.String]::Concat($KustoToolsPath, '\Kusto.Data.dll')

    Write-ToLog -Stream 'Information' -MessageData "Loading Kusto.Data.dll from path: '$KustoToolsDataDllPath'."
    try {
        $ErrorActionPreference = 'Stop'
        [System.Reflection.Assembly]::LoadFrom($KustoToolsDataDllPath)
    }
    catch {
        Write-ToLog -Stream 'Error' -MessageData "An error occurred while loading Kusto.Data.dll from path: '$KustoToolsDataDllPath'."
        throw
    }

    # Build connection
    Write-ToLog -Stream 'Information' -MessageData "Building Kusto connection string to cluster: '$clusterUrl' and database: '$ADXDatabaseName'."
    $kcsb = New-Object Kusto.Data.KustoConnectionStringBuilder ($clusterUrl, $ADXDatabaseName)

    # Add System-Assigned Managed Identity (MSI) authentication to the connection string
    Write-ToLog -Stream 'Information' -MessageData 'Adding System-Assigned Managed Identity (MSI) authentication to Kusto connection string.'
    $kcsb = $kcsb.WithAadSystemManagedIdentity()

    # ← Admin provider, not query provider
    Write-ToLog -Stream 'Information' -MessageData "Creating Kusto Admin Provider to cluster: '$clusterUrl' and database: '$ADXDatabaseName'."
    $adminProvider = [Kusto.Data.Net.Client.KustoClientFactory]::CreateCslAdminProvider($kcsb)

    # Request properties
    Write-ToLog -Stream 'Information' -MessageData "Creating Kusto Client Request Properties with timeout of: '$ADXTimeoutMinutes' minutes."
    $crp = New-Object Kusto.Data.Common.ClientRequestProperties
    $crp.ClientRequestId = 'MigrationScript.Append.' + [Guid]::NewGuid().ToString()
    $crp.SetOption(
        [Kusto.Data.Common.ClientRequestProperties]::OptionServerTimeout,
        [TimeSpan]::FromMinutes($ADXTimeoutMinutes)   # ← bump timeout, appends run long
    )

    $command = @"
.set-or-append $ADXTableName <|
cluster('$LAWClusterURI')
.database('$LAWDBName')
.$SearchJobTableName
| where _OriginalTimeGenerated between (datetime($FromDateTimeUTCDateTimeStringLowercase) .. datetime($NextTimeBlockStringLowercase))
| project
    TimeGenerated = _OriginalTimeGenerated,
    Computer, EventTime, Facility, HostIP, HostName,
    ProcessID, ProcessName, SeverityLevel, SourceSystem,
    SyslogMessage, Type = _OriginalType,
    TenantId = toguid(_OriginalTenantId),
    _ResourceId,
    _SubscriptionId = guid(null),
    _TimeReceived = now()
"@
    Write-ToLog -Stream 'Information' -MessageData "Querying for logs between: '$FromDateTimeUTCDateTimeStringLowercase' and: '$NextTimeBlockStringLowercase'."

    # ← ExecuteControlCommand, not ExecuteQuery
    $reader   = $adminProvider.ExecuteControlCommand($ADXDatabaseName, $command, $crp)
    $table    = [Kusto.Cloud.Platform.Data.ExtendedDataReader]::ToDataSet($reader).Tables[0]

    # Async command returns a single row with the OperationId
    $opId = $table.Rows[0]['OperationId']
    Write-Host "Submitted — OperationId: $opId"

    # --- Poll for completion ---
    $pollCommand = ".show operations $opId"
    do {
        Start-Sleep -Seconds 15
        $pollReader = $adminProvider.ExecuteControlCommand($ADXDatabaseName, $pollCommand, $crp)
        $pollTable  = [Kusto.Cloud.Platform.Data.ExtendedDataReader]::ToDataSet($pollReader).Tables[0]
        $state      = $pollTable.Rows[0]['State']
        Write-Host "  ↻ $state"
    } while ($state -notin @('Completed', 'Failed', 'Abandoned'))

    if ($state -ne 'Completed') {
        Write-Warning "❌ Failed — check: .show operation details $opId"
    }
    else {
        Write-Host '✅ Done'
    }
}
### END: GET & EXPORT LOGS FROM LAW ###
#### Push output binding ####
[System.String]$BodyMessage = 'Done querying and exporting. Exiting.'
Write-ToLog -Stream 'Information' -MessageData $BodyMessage

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })