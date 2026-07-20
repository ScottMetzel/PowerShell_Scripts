# Requires Az.Accounts and Az.OperationalInsights
# Connect-AzAccount beforehand, or allow this script to prompt for sign in.

param(
    [Parameter(Mandatory = $true)]
    [System.String]$LAWResourceId,

    [Parameter(Mandatory = $true)]
    [System.String]$ADXClusterUri,

    [Parameter(Mandatory = $true)]
    [System.String]$ADXDatabaseName,

    [Parameter(Mandatory = $true)]
    [System.String]$ADXTableName,

    [Parameter(Mandatory = $false)]
    [System.String]$LATableName = 'SecurityEvent',

    [Parameter(Mandatory = $false)]
    [System.String]$EntraTenantId,

    [Parameter(Mandatory = $false)]
    [System.String]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [System.Boolean]$PreviewOnly = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PlainTextToken {
    param(
        [Parameter(Mandatory = $true)]
        [System.Object]$AccessTokenResponse
    )

    $tokenValue = $AccessTokenResponse.Token

    if ($tokenValue -is [System.Security.SecureString]) {
        $ptr = [System.IntPtr]::Zero
        try {
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenValue)
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        }
        finally {
            if ($ptr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
        }
    }

    return [System.String]$tokenValue
}

function Convert-LATypeToADXType {
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$LADataType
    )

    switch ($LADataType.ToLowerInvariant()) {
        'string' {
            'string' 
        }
        'dynamic' {
            'dynamic' 
        }
        'guid' {
            'guid' 
        }
        'bool' {
            'bool' 
        }
        'boolean' {
            'bool' 
        }
        'datetime' {
            'datetime' 
        }
        'date' {
            'datetime' 
        }
        'timespan' {
            'timespan' 
        }
        'long' {
            'long' 
        }
        'int' {
            'int' 
        }
        'int32' {
            'int' 
        }
        'int64' {
            'long' 
        }
        'real' {
            'real' 
        }
        'double' {
            'real' 
        }
        'decimal' {
            'decimal' 
        }
        default {
            'string' 
        }
    }
}

function Split-ResourceId {
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$ResourceId
    )

    $segments = $ResourceId.Trim('/').Split('/')

    if ($segments.Count -lt 8) {
        throw "Resource ID '$ResourceId' does not appear valid."
    }

    [PSCustomObject]@{
        SubscriptionId    = $segments[1]
        ResourceGroupName = $segments[3]
        ResourceName      = $segments[-1]
    }
}

Write-Verbose -Message 'Importing required Az modules.'
Import-Module -Name Az.Accounts -ErrorAction Stop
Import-Module -Name Az.OperationalInsights -ErrorAction Stop

$lawResource = Split-ResourceId -ResourceId $LAWResourceId

if (-not (Get-AzContext)) {
    if ([System.String]::IsNullOrWhiteSpace($EntraTenantId)) {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
    elseif ([System.String]::IsNullOrWhiteSpace($SubscriptionId)) {
        Connect-AzAccount -Tenant $EntraTenantId -ErrorAction Stop | Out-Null
    }
    else {
        Connect-AzAccount -Tenant $EntraTenantId -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    }
}
elseif (-not [System.String]::IsNullOrWhiteSpace($SubscriptionId)) {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}

Write-Verbose -Message "Getting Log Analytics workspace '$($lawResource.ResourceName)' in resource group '$($lawResource.ResourceGroupName)'."
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $lawResource.ResourceGroupName -Name $lawResource.ResourceName -ErrorAction Stop

$schemaQuery = @"
$LATableName
| getschema
| project ColumnName, DataType
| order by ColumnName asc
"@

Write-Verbose -Message "Querying schema from Log Analytics table '$LATableName'."
$schemaResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspace.CustomerId -Query $schemaQuery -ErrorAction Stop

if (-not $schemaResult.Results -or $schemaResult.Results.Count -eq 0) {
    throw "No schema rows were returned from table '$LATableName'."
}

$columnDefinitions = [System.Collections.Generic.List[string]]::new()

foreach ($row in $schemaResult.Results) {
    $adxType = Convert-LATypeToADXType -LADataType ([System.String]$row.DataType)
    $escapedColumnName = ([System.String]$row.ColumnName).Replace(']', ']]')
    $columnDefinitions.Add("['$escapedColumnName']:$adxType")
}

$escapedTableName = $ADXTableName.Replace(']', ']]')

$createMergeTableCommand = @"
.create-merge table ['$escapedTableName'] (
    $($columnDefinitions -join ",`n    ")
)
"@

Write-Host 'Generated ADX command:'
Write-Host $createMergeTableCommand

if ($PreviewOnly) {
    Write-Host 'PreviewOnly is true. No changes were made in ADX.'
    return
}

$normalizedClusterUri = $ADXClusterUri.TrimEnd('/')
$managementEndpoint = "$normalizedClusterUri/v1/rest/mgmt"

Write-Verbose -Message 'Acquiring ADX access token.'
$adxTokenResponse = if ([System.String]::IsNullOrWhiteSpace($EntraTenantId)) {
    Get-AzAccessToken -ResourceUrl 'https://kusto.kusto.windows.net' -ErrorAction Stop
}
else {
    Get-AzAccessToken -ResourceUrl 'https://kusto.kusto.windows.net' -TenantId $EntraTenantId -ErrorAction Stop
}

$adxToken = Get-PlainTextToken -AccessTokenResponse $adxTokenResponse

$requestBody = @{
    db  = $ADXDatabaseName
    csl = $createMergeTableCommand
} | ConvertTo-Json -Depth 5

$headers = @{
    Authorization  = "Bearer $adxToken"
    'Content-Type' = 'application/json; charset=utf-8'
}

Write-Verbose -Message "Applying schema to ADX table '$ADXTableName' in database '$ADXDatabaseName'."
$managementResponse = Invoke-RestMethod -Method Post -Uri $managementEndpoint -Headers $headers -Body $requestBody -ErrorAction Stop

Write-Host 'ADX schema apply command completed successfully.'
Write-Output $managementResponse
