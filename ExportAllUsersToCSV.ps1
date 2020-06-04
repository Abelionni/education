
Import-Module ActiveDirectory

$users = Get-ADUser -Filter "*" -SearchBase "OU=IACA,DC=edu,DC=ecole,DC=org" -SearchScope Subtree

$export = New-Object System.Collections.Generic.List[System.Object]

ForEach($user in $users) {

    $adUser = Get-ADUser -Identity "$user" -Properties GivenName,Surname,Department,EmailAddress

    $userObject = New-Object System.Object
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "first_name" -Value $adUser.GivenName
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "last_name" -Value $adUser.Surname
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "email_address" -Value $adUser.EmailAddress
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "grade_level" -Value $adUser.Department

   $export.Add($userObject)

}


$export | export-csv -Path "C:\test.csv" -NoTypeInformation
