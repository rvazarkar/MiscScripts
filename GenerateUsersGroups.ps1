Import-Module ActiveDirectory

$total = 300000
for ($userIndex=0; $userIndex -lt $total; $userIndex++) { 
    $userID = "{0:000000}" -f ($userIndex + 1)
    $userName = "test.user$userID"
    $groupName = "test.group$userID"
    $var = Get-Random -minimum 1 -maximum $userIndex
    $second = "{0:000000}" -f $var

    if ($userIndex % 1000 -eq 0){
        Write-Host "Creating user" ($userIndex + 1) "of" $total ":" $userName
    } 

    New-ADUser -AccountPassword (ConvertTo-SecureString "AAaaAAaa11!!11" -AsPlainText -Force) -Description ("TEST ACCOUNT " + $userID + ": This user account does not represent a real user and is meant for test purposes only") -DisplayName "Test User ($userID)" -Enabled $true -GivenName "Test" -Name "Test User ($userID)" -SamAccountName $userName

    New-ADGroup -Name "Test Group ($userID)" -SamAccountName $groupName -GroupCategory Security -GroupScope Global -DisplayName "Test Group ($userID)"
    Add-ADGroupMember $groupName $userName, "test.user$second"
}
