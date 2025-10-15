# Add a requires statement for PowerShell v7
param (
    [System.String]$FilePath,
    [ValidateScript(
        {
            (($_ -split "/").Count -eq 9) -and (($_ -split "/")[1] -eq "subscriptions") -and ([System.Guid]::TryParse(($_ -split "/")[2], [System.Management.Automation.PSReference]([System.Guid]::empty))) -and (($_ -split "/")[3] -eq "resourceGroups") -and (($_ -split "/")[5] -eq "providers") -and (($_ -split "/")[6] -eq "Microsoft.Dns") -and (($_ -split "/")[7] -in @("publicDnsZones", "privateDnsZones"))
        }
    )]
    [System.String]$AzDNSZoneResourceID,
    [ValidateSet(
        'Public',
        'Private',
        IgnoreCase = $true
    )]
    [System.String]$DNSZoneType
)
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Split DNS Zone Resource ID into components
[System.String]$DNSZoneSubscriptionID = $AzDNSZoneResourceID.Split("/")[2]
[System.String]$DNSZoneResourceGroupName = $AzDNSZoneResourceID.Split("/")[4]
# Private DNS Zone Resource ID Example: /subscriptions/225d8fd1-bd45-4959-8ccf-28a626893d92/resourceGroups/prod-rg-privatednszones-01/providers/Microsoft.Network/privateDnsZones/privatelink.servicebus.windows.net
# Public DNS Zone Resource ID Example: /subscriptions/225d8fd1-bd45-4959-8ccf-28a626893d92/resourceGroups/Prod-RG-PublicDNSZones-01/providers/Microsoft.Network/dnsZones/thebestdnszoneever.com
[System.String]$DNSZoneType = $AzDNSZoneResourceID.Split("/")[7]
[System.String]$DNSZoneName = $AzDNSZoneResourceID.Split("/")[-1]

### BEGIN: TEST CSV PATH ###
Write-Information -MessageData "Testing path: '$FilePath' to CSV."

$TestPath = Get-Item -Path $FilePath -ErrorAction SilentlyContinue

if ($TestPath) {
    Write-Information -MessageData "Found CSV at path: '$FilePath'."
}
else {
    Write-Error -Message "CSV at path: '$FilePath' not found. Please check the path and try again."
    throw
}
### END: TEST CSV PATH ###
### BEGIN: TEST CSV VALIDITY ###
Write-Information -MessageData "Importing CSV at path: '$FilePath'."
$ImportCSV = Import-Csv -Path $FilePath -Encoding utf8 -Delimiter ","

Write-Information -MessageData "Testing CSV validity."
if ($true -eq $ImportCSV.Name) {
    Write-Information -MessageData "CSV 'Name' Header found."
}
else {
    Write-Error -Message "CSV 'Name' Header not found. Please check the CSV and try again."
    throw
}

if ($true -eq $ImportCSV.Type) {
    Write-Information -MessageData "CSV 'Type' Header found."
}
else {
    Write-Error -Message "CSV 'Type' Header not found. Please check the CSV and try again."
    throw
}

if ($true -eq $ImportCSV.TTL) {
    Write-Information -MessageData "CSV 'TTL' Header found."
}
else {
    Write-Error -Message "CSV 'TTL' Header not found. Please check the CSV and try again."
    throw
}

if ($true -eq $ImportCSV.Data) {
    Write-Information -MessageData "CSV 'Data' Header found."
}
else {
    Write-Error -Message "CSV 'Data' Header not found. Please check the CSV and try again."
    throw
}
# Headers to check: Name, Type, TTL, Data
### END: TEST CSV VALIDITY ###
### BEGIN: TEST AZURE DNS ZONE PRESENCE ###
Write-Information -MessageData "Testing presence of Azure DNS Zone"

switch ($DNSZoneType) {
    "privateDnsZones" {
        Write-Information -MessageData "Getting Private DNS Zone: '$DNSZoneName' in Resource Group: '$DNSZoneResourceGroupName'."
        $GetDNSZone = Get-AzPrivateDnsZone -ResourceGroupName $DNSZoneResourceGroupName -Name $DNSZoneName -ErrorAction SilentlyContinue

    }
    "dnsZones" {
        Write-Information -MessageData "Getting Public DNS Zone: '$DNSZoneName' in Resource Group: '$DNSZoneResourceGroupName'."
        $GetDNSZone = Get-AzDnsZone -ResourceGroupName $DNSZoneResourceGroupName -Name $DNSZoneName -ErrorAction SilentlyContinue
    }
    default {
        Write-Error -Message "Azure DNS Zone Type not determined. Please check the zone and try again."
        throw
    }
}

if ($GetDNSZone) {
    Write-Information -MessageData "Azure DNS Zone: '$DNSZoneName' found in Resource Group: '$DNSZoneResourceGroupName'."
}
else {
    Write-Error -Message "Azure DNS Zone: '$DNSZoneName' not found in Resource Group: '$DNSZoneResourceGroupName'. Please check the zone and try again."
    throw
}
### END: TEST AZURE DNS ZONE PRESENCE ###
### BEGIN: ADD RECORDS FROM CSV TO AZURE DNS ZONE ###
[System.Int32]$i = 1
[System.Int32]$TotalRecords = $ImportCSV.Count
foreach ($Record in $ImportCSV) {
    [System.String]$RecordName = $Record.Name
    [System.String]$RecordType = $Record.Type
    [System.Int32]$RecordTTL = $Record.TTL
    [System.String]$RecordData = $Record.Data
    Write-Information -MessageData "Adding record: '$RecordName'. '$i' of: '$TotalRecords'."

    switch ($DNSZoneType) {
        "privateDnsZones" {
            switch ($RecordType.ToUpper()) {
                "A" {
                    Add-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType A -Ttl $RecordTTL -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -IPv4Address $RecordData) -ErrorAction Stop
                }
                "AAAA" {
                    Add-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType AAAA -Ttl $RecordTTL -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -IPv6Address $RecordData) -ErrorAction Stop
                }
                "CNAME" {
                    Add-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType CNAME -Ttl $RecordTTL -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -Cname $RecordData) -ErrorAction Stop
                }
                "MX" {
                    # MX record data format: preference mail-exchanger
                    $MXParts = $RecordData.Split(" ")
                    if ($MXParts.Count -ne 2) {
                        Write-Error -Message "Invalid MX record data format for record: '$RecordName'. Expected format: 'preference mail-exchanger'."
                        throw
                    }
                    $Preference = [System.Int32]$MXParts[0]
                    $MailExchanger = $MXParts[1]
                    Add-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType MX -Ttl $RecordTTL -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -MxPreference $Preference -MxExchange $MailExchanger) -ErrorAction Stop
                }
                "TXT" {
                    Add-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType TXT -Ttl $RecordTTL -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -Value @($RecordData)) -ErrorAction Stop
                }
                default {
                    Write-Error -Message "Unsupported record type: '$RecordType' for Private DNS Zone. Supported types: A, AAAA, CNAME, MX, TXT."
                    throw
                }
            }
        }
        "dnsZones" {
            switch ($RecordType.ToUpper()) {
                "A" {
                    Add-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType A -Ttl $RecordTTL -DnsRecords (New-AzDnsRecordConfig -IPv4Address $RecordData) -ErrorAction Stop
                }
                "AAAA" {
                    Add-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType AAAA -Ttl $RecordTTL -DnsRecords (New-AzDnsRecordConfig -IPv6Address $RecordData) -ErrorAction Stop
                }
                "CNAME" {
                    Add-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType CNAME -Ttl $RecordTTL -DnsRecords (New-AzDnsRecordConfig -Cname $RecordData) -ErrorAction Stop
                }
                "MX" {
                    # MX record data format: preference mail-exchanger
                    $MXParts = $RecordData.Split(" ")
                    if ($MXParts.Count -ne 2) {
                        Write-Error -Message "Invalid MX record data format for record: '$RecordName'. Expected format: 'preference mail-exchanger'."
                        throw
                    }
                    $Preference = [System.Int32]$MXParts[0]
                    $MailExchanger = $MXParts[1]
                    Add-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType MX -Ttl $RecordTTL -DnsRecords (New-AzDnsRecordConfig -MxPreference $Preference -MxExchange $MailExchanger) -ErrorAction Stop
                }
                "TXT" {
                    Add-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType TXT -Ttl $RecordTTL -DnsRecords (New-AzDnsRecordConfig -Value @($RecordData)) -ErrorAction Stop
                }
                default {
                    Write-Error -Message "Unsupported record type: '$RecordType' for Public DNS Zone. Supported types: A, AAAA, CNAME, MX, TXT."
                    throw
                }
            }
        }
        default {
            Write-Error -Message "Azure DNS Zone Type not determined. Please check the zone and try again."
            throw
        }
    }
    $i++
}
### END: ADD RECORDS FROM CSV TO AZURE DNS ZONE ###