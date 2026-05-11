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
$clusterUrl   = 'https://{your-cluster}.{region}.kusto.windows.net;Fed=True'
$databaseName = '{your-db}'
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
        'Az.Accounts',
        'Az.Kusto',
        'Az.Resources',
        'Az.Storage'
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
    $OutDirFullPath = $Using:OutDirFullPath
    $ctx = $Using:ctx
    $StorageAccountContainerName = $Using:StorageAccountContainerName
    $IsSearchJob = $Using:IsSearchJob
    $clusterUrl   = $Using:clusterUrl
    $databaseName = $Using:databaseName
    $LAWClusterURI = $Using:LAWClusterURI
    $LAWDBName = $Using:LAWDBName


    [System.DateTime]$FromDateTimeUTCDateTime = $_.Key
    [System.DateTime]$NextTimeBlock = $_.Value

    # Slice via KQL time filter (portable and explicit)
    [System.String]$FromDateTimeUTCDateTimeStringLowercase = $FromDateTimeUTCDateTime.ToString('o')
    [System.String]$NextTimeBlockStringLowercase = $NextTimeBlock.ToString('o')

    # Load SDK — point to wherever you have Kusto.Data.dll
    $packagesRoot = Resolve-Path '..\bin\microsoft.azure.kusto.tools.14.1.2\tools\net8.0'
    [System.Reflection.Assembly]::LoadFrom("$packagesRoot\Kusto.Data.dll")

    # Build connection
    $kcsb = New-Object Kusto.Data.KustoConnectionStringBuilder ($clusterUrl, $databaseName)

    # ← Admin provider, not query provider
    $adminProvider = [Kusto.Data.Net.Client.KustoClientFactory]::CreateCslAdminProvider($kcsb)

    # Request properties
    $crp = New-Object Kusto.Data.Common.ClientRequestProperties
    $crp.ClientRequestId = 'MigrationScript.Append.' + [Guid]::NewGuid().ToString()
    $crp.SetOption(
        [Kusto.Data.Common.ClientRequestProperties]::OptionServerTimeout,
        [TimeSpan]::FromMinutes(10)   # ← bump timeout, appends run long
    )

    $command = @"
.set-or-append Syslog <|
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
    $reader   = $adminProvider.ExecuteControlCommand($databaseName, $command, $crp)
    $table    = [Kusto.Cloud.Platform.Data.ExtendedDataReader]::ToDataSet($reader).Tables[0]

    # Async command returns a single row with the OperationId
    $opId = $table.Rows[0]['OperationId']
    Write-Host "Submitted — OperationId: $opId"

    # --- Poll for completion ---
    $pollCommand = ".show operations $opId"
    do {
        Start-Sleep -Seconds 15
        $pollReader = $adminProvider.ExecuteControlCommand($databaseName, $pollCommand, $crp)
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
[System.String]$BodyMessage = 'Exiting!'
Write-ToLog -Stream 'Information' -MessageData $BodyMessage

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $BodyMessage
    })