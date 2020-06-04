$groups = Get-ADGroup -Filter "*" -SearchBase "OU=IACA,DC=edu,DC=ecole,DC=org"

ForEach ($group in $groups) {
    $groupName = $group.SamAccountName.ToLower()

    Set-ADGroup $group -Replace @{mail="$groupName@ecole.org"}
}