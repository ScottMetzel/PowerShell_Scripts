param (
    [System.String]$FilePath,
    [ValidateScript(
        {
            (($_ -split '/').Count -eq 9) -and (($_ -split '/')[1] -eq 'subscriptions') -and ([System.Guid]::TryParse(($_ -split '/')[2], [System.Management.Automation.PSReference]([System.Guid]::empty))) -and (($_ -split '/')[3] -eq 'resourceGroups') -and (($_ -split '/')[5] -eq 'providers') -and (($_ -split '/')[6] -eq 'Microsoft.Network') -and (($_ -split '/')[7] -in @('dnszones', 'privateDnsZones'))
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
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# Split DNS Zone Resource ID into components
[System.String]$DNSZoneSubscriptionID = $AzDNSZoneResourceID.Split('/')[2]

Write-Host $DNSZoneSubscriptionID

[System.String]$DNSZoneResourceGroupName = $AzDNSZoneResourceID.Split('/')[4]

# Private DNS Zone Resource ID Example: /subscriptions/225d8fd1-bd45-4959-8ccf-28a626893d92/resourceGroups/prod-rg-privatednszones-01/providers/Microsoft.Network/privateDnsZones/privatelink.servicebus.windows.net
# Public DNS Zone Resource ID Example: /subscriptions/225d8fd1-bd45-4959-8ccf-28a626893d92/resourceGroups/Prod-RG-PublicDNSZones-01/providers/Microsoft.Network/dnsZones/thebestdnszoneever.com

[System.String]$DNSZoneType = $AzDNSZoneResourceID.Split('/')[7]

[System.String]$DNSZoneName = $AzDNSZoneResourceID.Split('/')[-1]

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
$ImportCSV = Import-Csv -Path $FilePath -Encoding utf8 -Delimiter ','

Write-Information -MessageData 'Testing CSV validity.'
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
Write-Information -MessageData 'Testing presence of Azure DNS Zone'

switch ($DNSZoneType) {
    'privateDnsZones' {
        Write-Information -MessageData "Getting Private DNS Zone: '$DNSZoneName' in Resource Group: '$DNSZoneResourceGroupName'."
        $GetDNSZone = Get-AzPrivateDnsZone -ResourceGroupName $DNSZoneResourceGroupName -Name $DNSZoneName -ErrorAction SilentlyContinue

    }
    'dnsZones' {
        Write-Information -MessageData "Getting Public DNS Zone: '$DNSZoneName' in Resource Group: '$DNSZoneResourceGroupName'."
        $GetDNSZone = Get-AzDnsZone -ResourceGroupName $DNSZoneResourceGroupName -Name $DNSZoneName -ErrorAction SilentlyContinue
    }
    default {
        Write-Error -Message 'Azure DNS Zone Type not determined. Please check the zone and try again.'
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

Write-Information -MessageData $TotalRecords

foreach ($Record in $ImportCSV) {
    [System.String]$RecordName = $Record.Name
    [System.String]$RecordType = $Record.Type
    [System.Int32]$RecordTTL = $Record.TTL
    [System.String]$RecordData = $Record.Data

    Write-Information -MessageData "Working on record: '$RecordName'. '$i' of: '$TotalRecords'."

    if ($RecordName -in @('', $null) -or [string]::IsNullOrWhiteSpace($RecordName)) {
        Write-Warning -Message "Record Name is empty or null. Using '@' for the zone apex."
        [System.String]$RecordName = '@'
    }

    if ([string]::IsNullOrWhiteSpace($RecordType) -or $RecordType -in @('', $null)) {
        Write-Error -Message "Record Type is empty or null for record: '$RecordName'. Please check the CSV and try again."
        throw
    }

    if ([string]::IsNullOrWhiteSpace($RecordData) -or $RecordData -in @('', $null)) {
        Write-Error -Message "Record Data is empty or null for record: '$RecordName'. Please check the CSV and try again."
        throw
    }

    if ([string]::IsNullOrWhiteSpace($RecordTTL) -or $RecordTTL -in @('', $null)) {
        Write-Warning -Message "Record TTL is empty or null for record: '$RecordName'. Using default TTL of 3600 seconds."
        [System.Int32]$RecordTTL = 3600
    }

    switch ($DNSZoneType) {
        'privateDnsZones' {
            $GetExistingPrivateDnsRecordSet = Get-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType $RecordType -ErrorAction SilentlyContinue
            if ($GetExistingPrivateDnsRecordSet) {
                Write-Warning -Message "DNS Record Set: '$RecordName' of type: '$RecordType' already exists in Private DNS Zone: '$DNSZoneName'. Skipping creation."
                $i++
                continue
            }
            else {
                Write-Information -MessageData "Preparing to create Private DNS Record Set: '$RecordName' of type: '$RecordType' in Private DNS Zone: '$DNSZoneName'."
                Remove-Variable -Name NewPrivateDnsRecordConfig -ErrorAction SilentlyContinue

                switch ($RecordType.ToUpper()) {
                    'A' {
                        Write-Information -MessageData "Creating A record with IP: $RecordData"
                        $NewPrivateDnsRecordConfig = New-AzPrivateDnsRecordConfig -Ipv4Address $RecordData
                    }
                    'AAAA' {
                        Write-Information -MessageData "Creating AAAA record with IP: $RecordData"
                        $NewPrivateDnsRecordConfig = New-AzPrivateDnsRecordConfig -Ipv6Address $RecordData
                    }
                    'CNAME' {
                        Write-Information -MessageData "Creating CNAME record with alias: $RecordData"
                        $NewPrivateDnsRecordConfig = New-AzPrivateDnsRecordConfig -Cname $RecordData
                    }
                    'MX' {
                        # MX record data format: preference mail-exchanger
                        $MXParts = $RecordData.Split(' ')
                        if ($MXParts.Count -ne 2) {
                            Write-Error -Message "Invalid MX record data format for record: '$RecordName'. Expected format: 'preference mail-exchanger', e.g. '10 mail.example.com'."
                            throw
                        }
                        $Preference = [System.Int32]$MXParts[0]
                        $MailExchanger = $MXParts[1]
                        Write-Information -MessageData "Creating MX record with preference: $Preference and mail exchanger: $MailExchanger"
                        $NewPrivateDnsRecordConfig = New-AzPrivateDnsRecordConfig -MxPreference $Preference -MxExchange $MailExchanger
                    }
                    'TXT' {
                        Write-Information -MessageData "Creating TXT record with value: $RecordData"
                        $NewPrivateDnsRecordConfig = New-AzPrivateDnsRecordConfig -Value @($RecordData)
                    }
                    default {
                        Write-Error -Message "Unsupported record type: '$RecordType' for Private DNS Zone. Supported types: A, AAAA, CNAME, MX, TXT."
                        throw
                    }
                }

                try {
                    $ErrorActionPreference = 'Stop'
                    Write-Information -MessageData "Creating Private DNS Record Set: '$RecordName' of type: '$RecordType' in Private DNS Zone: '$DNSZoneName'."
                    New-AzPrivateDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType $RecordType.ToUpper() -Ttl $RecordTTL -PrivateDnsRecords $NewPrivateDnsRecordConfig -ErrorAction Stop
                }
                catch {
                    Write-Error -Message "Failed to create Private DNS Record Set: '$RecordName' of type: '$RecordType' in Private DNS Zone: '$DNSZoneName'. Error: $_"
                }
            }
        }
        'dnsZones' {
            $GetExistingPublicDnsRecordSet = Get-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType $RecordType -ErrorAction SilentlyContinue
            if ($GetExistingPublicDnsRecordSet) {
                Write-Warning -Message "DNS Record Set: '$RecordName' of type: '$RecordType' already exists in Public DNS Zone: '$DNSZoneName'. Skipping creation."
                $i++
                continue
            }
            else {
                Write-Information -MessageData "Preparing to create DNS Record Set: '$RecordName' of type: '$RecordType' in DNS Zone: '$DNSZoneName'."
                Remove-Variable -Name NewPublicDnsRecordConfig -ErrorAction SilentlyContinue
                switch ($RecordType.ToUpper()) {
                    'A' {
                        Write-Information -MessageData "Creating A record with IP: $RecordData"
                        $NewPublicDnsRecordConfig = New-AzDnsRecordConfig -Ipv4Address $RecordData
                    }
                    'AAAA' {
                        Write-Information -MessageData "Creating AAAA record with IP: $RecordData"
                        $NewPublicDnsRecordConfig = New-AzDnsRecordConfig -Ipv6Address $RecordData
                    }
                    'CNAME' {
                        Write-Information -MessageData "Creating CNAME record with alias: $RecordData"
                        $NewPublicDnsRecordConfig = New-AzDnsRecordConfig -Cname $RecordData
                    }
                    'MX' {
                        # MX record data format: preference mail-exchanger
                        $MXParts = $RecordData.Split(' ')
                        if ($MXParts.Count -ne 2) {
                            Write-Error -Message "Invalid MX record data format for record: '$RecordName'. Expected format: 'preference mail-exchanger', e.g. '10 mail.example.com'"
                            throw
                        }
                        $Preference = [System.Int32]$MXParts[0]
                        $MailExchanger = $MXParts[1]
                        Write-Information -MessageData "Creating MX record with preference: $Preference and mail exchanger: $MailExchanger"
                        $NewPublicDnsRecordConfig = New-AzDnsRecordConfig -Preference $Preference -Exchange $MailExchanger
                    }
                    'TXT' {
                        Write-Information -MessageData "Creating TXT record with value: $RecordData"
                        $NewPublicDnsRecordConfig = New-AzDnsRecordConfig -Value @($RecordData)
                    }
                    default {
                        Write-Error -Message "Unsupported record type: '$RecordType' for Public DNS Zone. Supported types: A, AAAA, CNAME, MX, TXT."
                        throw
                    }
                }

                try {
                    $ErrorActionPreference = 'Stop'
                    Write-Information -MessageData "Creating DNS Record Set: '$RecordName' of type: '$RecordType' in DNS Zone: '$DNSZoneName'."
                    New-AzDnsRecordSet -ResourceGroupName $DNSZoneResourceGroupName -ZoneName $DNSZoneName -Name $RecordName -RecordType $RecordType.ToUpper() -Ttl $RecordTTL -DnsRecords $NewPublicDnsRecordConfig -ErrorAction Stop
                }
                catch {
                    Write-Error -Message "Failed to create DNS Record Set: '$RecordName' of type: '$RecordType' in DNS Zone: '$DNSZoneName'. Error: $_"
                }
            }

        }
        default {
            Write-Error -Message 'Azure DNS Zone Type not determined. Please check the zone and try again.'
            throw
        }
    }
    $i++
}
Write-Information -MessageData 'All done! Exiting.'
### END: ADD RECORDS FROM CSV TO AZURE DNS ZONE ###