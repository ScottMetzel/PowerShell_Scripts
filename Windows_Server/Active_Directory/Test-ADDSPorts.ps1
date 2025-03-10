$InformationPreference = 'Continue'
[System.Collections.ArrayList]$TCPPorts = @(
    53,
    135,
    389,
    445,
    464,
    636,
    3268,
    3269
)

[System.String]$DestinationIPOrFQDN = ''

[System.Int32]$i = 1
[System.Int32]$TCPPortsCount = $TCPPorts.Count
foreach ($Port in $TCPPorts) {
    Write-Information -MessageData "Testing to: '$DestinationIPOrFQDN' over TCP port: '$Port'. Port: '$i' of: '$TCPPortsCount' ports."

    try {
        $ErrorActionPreference = 'Stop'
        Test-NetConnection -ComputerName $DestinationIPOrFQDN -Port $Port

        Start-Sleep -Seconds 5
    }
    catch {
        $_
    }
    $i++
}