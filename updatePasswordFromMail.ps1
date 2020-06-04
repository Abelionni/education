param (  
    [string]$csv = $(throw "-csv is required.")
)

$mailAndPassowrds = Import-Csv $csv -delimiter ";"

ForEach ($record in $mailAndPassowrds) {
    $mail = $record.MAIL
    $password = $record.MDP
    $SecPaswd= ConvertTo-SecureString –String "$password" –AsPlainText –Force


    $accounts = Get-ADUser -Filter { UserPrincipalName -Eq $mail } 

    ForEach ($account in $accounts) {
        Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $account
    }
}