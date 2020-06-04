
function Remove-Diacritics {
param ([String]$src = [String]::Empty)
  $normalized = $src.Normalize( [Text.NormalizationForm]::FormD )
  $sb = new-object Text.StringBuilder
  $normalized.ToCharArray() | % { 
    if( [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
      [void]$sb.Append($_)
    }
  }
  $sb.ToString()
}


function normalizeName($name) {
    return ((Remove-Diacritics $name) -replace "[^a-zA-Z0-9-]+", "").ToLower()
}

$allADUsers = Get-ADUser -Filter { UserPrincipalName -notlike "admin*" } -SearchBase "OU=IACA,DC=edu,DC=ecole,DC=org"

ForEach($adUserDN in $allADUsers) {
    $adUser = Get-ADUser -Identity $adUserDN -Properties GivenName,Surname,Department,EmailAddress,UserPrincipalName,DisplayName

    $normalizedFirstName = normalizeName $adUser.GivenName
    $normalizedLastName = normalizeName $adUser.Surname
    
    $currentEmailAddress = $adUser.EmailAddress
    $currentUPN = $adUser.UserPrincipalName

    $normalizedID = "$normalizedFirstName.$normalizedLastName@ecole.org"

    if ((-not $currentEmailAddress.StartsWith("$normalizedID")) -or (-not $currentUPN.StartsWith("$normalizedID"))) {
        echo $adUser.DisplayName

        if (-not $currentEmailAddress.StartsWith("$normalizedID")) {
            echo "    - Email address $currentEmailAddress should be $normalizedID"
        }

        if (-not $currentUPN.StartsWith("$normalizedID")) {
            echo "    - User principal name $currentUPN should be $normalizedID"
        }
        
        Set-ADUser -Identity $adUserDN -UserPrincipalName "$normalizedID"
        Set-ADUser -Identity $adUserDN -EmailAddress "$normalizedID"

        echo ""
    }

}