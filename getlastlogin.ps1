# Import the Active Directory module
Import-Module ActiveDirectory

# Define your domain controllers
$domainControllers = @("ldc-fb-dc-01.forchtbank.local", "cdc-fb-dc-01.forchtbank.local", "aznc-fb-dc-01.forchtbank.local")

# Define the list of users
$users = @("MSOL_89c7e66ac149", "SVCFBSQL", "ediscovery", "remotecredit", "svcfbcopier", "DebitCard", "DepHelp", "WiresOB", "NewAcctsExcep", "testmfa")

# Initialize an empty array to store results
$results = @()

# Loop through each user
foreach ($user in $users) {
    # Initialize an empty hashtable to store user information
    $userInfo = @{}

    # Loop through each domain controller
    foreach ($dc in $domainControllers) {
        # Get last login time from each domain controller
        $lastLogon = Get-ADUser $user -Server $dc -Properties LastLogon | Select-Object -ExpandProperty LastLogon

        # Convert last logon time to readable format
        $lastLogonFormatted = [DateTime]::FromFileTime($lastLogon)

        # Add last logon time for current domain controller to user information
        $userInfo[$dc] = $lastLogonFormatted
    }

    # Add user information to results array
    $results += New-Object PSObject -Property $userInfo
}

# Export results to a text file
$results | Export-Csv -Path "last_login_times.csv" -NoTypeInformation
