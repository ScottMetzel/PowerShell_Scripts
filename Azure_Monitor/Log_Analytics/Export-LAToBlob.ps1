# Requires Az.OperationalInsights
# Connect-AzAccount beforehand
### START: GET LA ###
param(
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
            [System.DateTime]$NewDateTime = New-Object DateTime

            [System.DateTime]::TryParseExact($_, 'yyyyMMddHHmmss',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None,
                [ref]$NewDateTime)
        }
    )]
    [System.String]$StartDateTimeUTC,
    [Parameter(
        Mandatory = $true
    )]
    [ValidateScript(
        {
            [System.DateTime]$NewDateTime = New-Object DateTime

            [System.DateTime]::TryParseExact($_, 'yyyyMMddHHmmss',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None,
                [ref]$NewDateTime)
        }
    )]
    [System.String]$EndDateTimeUTC,
    [System.Int32]$SliceMinutes = 15,
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$StorageAccountResourceID,
    [System.String]$OutDir = '.\la-export',
    [System.Boolean]$RemoveLALogs = $false,
    [System.String]$DeleteAPIVersion = '2023-09-01'
)
### START: CONNECT TO AZURE ###
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.Network'
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
[System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
Write-Verbose -Message $VerboseMessage
try {
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
}
catch {
    Write-Error -Message $_
}
### END: CONNECT TO AZURE ###
### START: READ FROM LAW ###
Write-Verbose -Message 'Getting Workspace'
$GetWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAResourceGroupName -Name $LAWorkspaceName

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Loop in fixed windows
[DateTime]$parsedDate = $null
[System.DateTime]$StartDateTimeUTCFormatted = Get-Date -Date ([System.DateTime]::TryParse($StartDateTimeUTC,[ref]$parsedDate)) -UFormat yyyyMMddHHmmss
[System.DateTime]$EndDateTimeUTCFormatted = Get-Date -Date $EndDateTimeUTCFormatted -UFormat yyyyMMddHHmmss
while ($StartDateTimeUTCFormatted -lt $EndDateTimeUTCFormatted) {
    $next = [datetime]::SpecifyKind($StartDateTimeUTCFormatted.AddMinutes($SliceMinutes), 'Utc')
    if ($next -gt $EndDateTimeUTCFormatted) {
        $next = $EndDateTimeUTCFormatted
    }

    $fileStamp = '{0:yyyyMMddHHmmss}-{1:yyyyMMddHHmmss}' -f $StartDateTimeUTCFormatted, $next
    $outFile   = Join-Path $OutDir "$LATableName-$fileStamp.jsonl"

    # Slice via KQL time filter (portable and explicit)
    $kql = @"
$LATableName
| where TimeGenerated between (datetime($($StartDateTimeUTCFormatted.ToString('o'))) .. datetime($($next.ToString('o'))))
| order by TimeGenerated asc
"@
    $resp = Invoke-AzOperationalInsightsQuery -Workspace $GetWorkspace -Query $kql
    #$resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $kql

    # Write JSON Lines (one row per line). Keep depth high for dynamic columns.
    [System.Int32]$i = 1
    [System.Int32]$QueryCount = $resp.Results.Count
    foreach ($row in $resp.Results) {
        Write-Verbose -Message "Exporting result: '$i' of: '$QueryCount' results."
        ($row | ConvertTo-Json -Depth 50 -Compress) | Out-File -FilePath $outFile -Append -Encoding utf8
        $i++
    }

    Write-Host "Exported slice $StartDateTimeUTCFormatted -> $next to $outFile"
    $StartDateTimeUTCFormatted = $next
}
### END: READ FROM LAW ###
### START: STORE IN BLOB ###
[System.Collections.ArrayList]$StorageAccountRIDArray = $StorageAccountResourceID.Split('/')

[System.String]$StorageAccountResourceGroupName = $StorageAccountRIDArray[4]
[System.String]$StorageAccountName = $StorageAccountRIDArray[-1]

Write-Verbose -Message "Getting storage account: '$StorageAccountName'."
$ctx = (Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName).Context

[System.String]$Now = Get-Date -Format FileDateTimeUniversal
[System.String]$ContainerName = ([System.String]::Concat($LATableName, '_', $Now)).ToLower()

New-AzStorageContainer -Name $ContainerName -Context $ctx -ErrorAction SilentlyContinue | Out-Null

Get-ChildItem $OutDir -Filter *.jsonl | ForEach-Object {
    [System.String]$BlobName = $_.Name
    Write-Verbose -Message "Uploading: '$BlobName'"
    Set-AzStorageBlobContent -Context $ctx -Container $ContainerName -File $_.FullName -Blob $BlobName -Force | Out-Null
}
### END: STORE IN BLOB ###
### START: DELETE FROM LA ###
if ($true -eq $RemoveLALogs) {
    Write-Warning -Message "Will remove Log Analytics logs from table: '$LATableName' between: '$StartDateTimeUTC' and: '$EndDateTimeUTC'."

    [System.String]$DeleteAPIURI = [System.String]::Concat('https://management.azure.com/subscriptions/',$LASubscriptionID,'/resourceGroups/', $LAResourceGroupName, '/providers/microsoft.OperationalInsights/workspaces/', $LAWorkspaceName, '/tables/',$LATableName,'/deleteData?api-version=',$DeleteAPIVersion)

    $DeleteAPIBody = @{
        filters = @(
            @{
                column   = 'TimeGenerated'
                operator = '>'
                value    = '2024-09-23T00:00:00'
            },
            @{
                column   = 'Resource'
                operator = '=='
                value    = 'VM-1'
            }
        )
    } | ConvertTo-Json -Depth 3
}
### END: DELETE FROM LA ###