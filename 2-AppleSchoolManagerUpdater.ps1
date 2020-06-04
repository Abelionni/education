### To run this script you must install Windows Management Framework 5.0 before https://www.microsoft.com/en-us/download/details.aspx?id=50395
### Be careful to get the right installation package for your server, 2012R2 isn't 2012

Import-Module ActiveDirectory

### Run
$clearFiles = $false
$dryRun = $false

### School settings

$asmLogin = "ID@sftp.apple.com"
$asmPassword = "PASS"
$asmServer = "upload.appleschoolcontent.com"
$asmServerPublicKey = "ecdsa-sha2-nistp256 256 62:e8:89:ea:7c:89:6b:b6:94:6c:e6:64:b2:ed:81:f5"

$asmStudentScope = "students"
$asmStaffScope = "staff"
$asmLocationScope = "locations"
$asmClassesScope = "classes"
$asmRostersScope = "rosters"
$asmCoursesScope = "courses"

# Export des cours depuis EDT
$edtCSVPath = "C:\Echange\ASM\EXP_COURS.csv"
$edtCSVDelimiter = ";"

$searchBasesByScope = @{$asmStudentScope = @("OU=ELEVES,OU=Users,OU=Site par défaut,OU=IACA,DC=edu,DC=ecole,DC=org"); $asmStaffScope = @("OU=PROFESSEURS,OU=Users,OU=Site par défaut,OU=IACA,DC=edu,DC=ecole,DC=org", "OU=PERSONNEL,OU=Users,OU=Site par défaut,OU=IACA,DC=edu,DC=ecole,DC=org", "OU=ADJOINTS,OU=Users,OU=Site par défaut,OU=IACA,DC=edu,DC=ecole,DC=org")}

$asmLocations = @(@{"location_id" = "Campus"; "location_name" = "Campus"})

$userIDField = "SamAccountName"
$usernameField = "SamAccountName"

####### Dependencies #######
function Load-Module ($m) {
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    } else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m -Verbose
        } else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            } else {
                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

Load-Module "WinSCP"
Load-Module "Pscx"

Add-Type -assembly "system.io.compression.filesystem"

### File import management

$importedCSVFromEDT = Import-Csv -Path $edtCSVPath -Delimiter $edtCSVDelimiter | select *,@{Name='instructor_id';Expression={""}} | select *,@{Name='clean_group';Expression={""}}
$cleanedCSVFromEDT = New-Object System.Collections.Generic.List[System.Object]

$allClassesID = New-Object System.Collections.Generic.List[System.Object]

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

$instructorIDList = New-Object System.Collections.Generic.List[System.Object]

ForEach($item in $importedCSVFromEDT) {
        $cleanClass = $item.CLASSE -replace "<.*>" -replace " " -replace "\."
        $cleanClass = $cleanClass.Trim()

        if ($cleanClass -match "^\[.*") {
            $cleanClass = $cleanClass -replace "\].*\[", "-" -replace "\].*$" -replace "\["
        } else {
            $cleanClass = $cleanClass -replace "^T", "0"
            $cleanClass = "0$cleanClass"
        }

        $cleanClass = $cleanClass.Trim()

        
        if ($cleanClass -match ".*-.*") {
            Write-Host "Error with $cleanClass from" $item.CLASSE
        }
            
        $item.clean_group = $cleanClass

        if ($item.clean_group -match "^02" -or $item.clean_group -match "^01" -or $item.clean_group -match "^00") {

            $teachers = New-Object System.Collections.Generic.List[System.Object]

            if ($item.PROF_PRENOM -match "," -and $item.PROF_NOM -match ",") {
                $firstnames = $item.PROF_PRENOM.Split(", ")
                $lastnames = $item.PROF_NOM.Split(", ")

                if ($firstnames.Count -eq $lastnames.Count) {
                    $total = $firstnames.Count
                    for ($i=0; $i -lt $total; $i++) {
                        $teachers.Add(@{"firstname" = $firstnames[$i]; "lastname" = $lastnames[$i]})
                    }
                } else {
                    continue
                }
            } else {
                $teachers = @(@{"firstname" = $item.PROF_PRENOM; "lastname" = $item.PROF_NOM})
            }

            $finalItem = @{}
            
            $finalItem.Add("MAT_CODE", $item.MAT_CODE)
            $finalItem.Add("MAT_LIBELLE", $item.MAT_LIBELLE)
            $finalItem.Add("clean_group", $item.clean_group)
            
            $numberOfTeacher = $teachers.Count

            $lastInstructorIndex = 1
            for ($teacherIndex=0; $teacherIndex -lt $numberOfTeacher; $teacherIndex++) {
                $teacherFirstname = $teachers[$teacherIndex]["firstname"]
                $teacherLastname = $teachers[$teacherIndex]["lastname"]

                Write-Host "Working on teacher $teacherIndex, $teacherFirstname $teacherLastname for $cleanClass," $item.MAT_LIBELLE

                $searchMethod = 0
                $continueLookup = $true
            
                Do {
                    switch ( $searchMethod )
                    {
                        0 {
                            Try {
                                $normalizedFirstName = normalizeName $teacherFirstname
                                $normalizedLastName = normalizeName $teacherLastname

                                $normalizedID = "$normalizedFirstName.$normalizedLastName@ecole.org"

                                $adTeacher = Get-ADUser -LDAPFilter "(userPrincipalName=$normalizedID)" -Properties $userIDField

                                #if (-not $adTeacher) {
                                #    Write-Host "User with UPN $normalizedID not found"
                                #}
                            } Catch {
                                Write-Warning "Invalid LDAP search string for UPN '$normalizedID'"
                                continue
                            }
                        }

                        1 {
                            Try {
                                $normalizedFirstName = normalizeName ($teacherFirstname -replace " ", "-")
                                $normalizedLastName = normalizeName $teacherLastname

                                $normalizedID = "$normalizedFirstName.$normalizedLastName@ecole.org"

                                $adTeacher = Get-ADUser -LDAPFilter "(userPrincipalName=$normalizedID)" -Properties $userIDField

                                #if (-not $adTeacher) {
                                #    Write-Host "User with UPN $normalizedID not found"
                                #}
                            } Catch {
                                Write-Warning "Invalid LDAP search string for UPN '$normalizedID'"
                                continue
                            }
                        }

                        2 {
                            Try {
                                $firstname = $teacherFirstname.Trim()
                                $lastname = $teacherLastname.Trim()
                                $adTeacher = Get-ADUser -LDAPFilter "(&(givenName=*$firstname*)(sn=*$lastname*))" -Properties $userIDField

                                #if (-not $adTeacher) {
                                #    Write-Host "User with firstname '$teacherFirstname' and lastname '$teacherLastname' not found"
                                #}
                            } Catch {
                                Write-Warning "Invalid LDAP search string composed with '$teacherFirstname' and '$teacherLastname'"
                                continue
                            }
                        }

                        3 {
                            Try {
                                $firstname = $teacherFirstname.Trim() -replace " ", "-"
                                $lastname = $teacherLastname.Trim()
                                $adTeacher = Get-ADUser -LDAPFilter "(&(givenName=*$firstname*)(sn=*$lastname*))" -Properties $userIDField

                                #if (-not $adTeacher) {
                                #    Write-Host "User with firstname '$teacherFirstname' and lastname '$teacherLastname' not found"
                                #}
                            } Catch {
                                Write-Warning "Invalid LDAP search string composed with '$teacherFirstname' and '$teacherLastname'"
                                continue
                            }
                        }

                        default {
                            Write-Warning "Impossible to found any teacher ID for '$teacherFirstname' '$teacherLastname'"
                            $continueLookup = $false
                        }
                    }

                    if ($adTeacher) {
                        $continueLookup = $false
                        
                        if ($teacherIndex -eq 0) {
                            $finalItem.Add("instructor_id", $adTeacher.$userIDField)
                        } else {
                            $instructorIndex = $lastInstructorIndex + 1
                            $finalItem.Add("instructor_id_$instructorIndex", $adTeacher.$userIDField)
                            $instructorIDList.Add("instructor_id_$instructorIndex")
                            $lastInstructorIndex = $instructorIndex
                        }
                    }

                    $searchMethod = $searchMethod + 1 
                } While ($continueLookup)
                
            }

            if ($finalItem["instructor_id"] -eq "") {
                Write-Warning "Impossible to find teacher ID for '$teacherFirstname' '$teacherLastname'"
                continue
            }
            $cleanedCSVFromEDT.Add($finalItem)
        }
}

### CSV mapping

$asmExportedCourses = $cleanedCSVFromEDT
$asmCoursesMapping = @{"course_id" = "MAT_CODE"; "course_number" = "MAT_CODE"; "course_name" = "MAT_LIBELLE"; }
$asmCoursesUniqueKey = "course_id"

$asmExportedClasses = $cleanedCSVFromEDT
$asmClassesMapping = @{}

$asmClassesMapping.Add("class_id", @("clean_group", "MAT_CODE"))
$asmClassesMapping.Add("class_number", @("clean_group", "MAT_CODE"))
$asmClassesMapping.Add("class_name", @("clean_group", "MAT_LIBELLE"))
$asmClassesMapping.Add("course_id", "MAT_CODE")
$asmClassesMapping.Add("instructor_id", "instructor_id")

$instructorIDList = $instructorIDList | Sort-Object | Get-Unique

ForEach($instructorID in $instructorIDList) {
    $asmClassesMapping.Add($instructorID,$instructorID)
}

$asmClassesUniqueKey = "class_id"

### Env

$TimeStamp = Get-Date -Format MM-dd-yyyy_HH_mm_ss
$baseFolder = "$Env:TEMP\AppleSchoolManagerUpdater"
$workingFolder = "$baseFolder\asmUpdate-$TimeStamp"
$finalArchive = "$workingFolder.zip"

########################

####### Configure script env #######

New-Item -ItemType Directory -Path "$workingFolder"
New-Item -ItemType Directory -Path "$workingFolder\csv"
New-Item -ItemType Directory -Path "$workingFolder\tmp"

$asmCredentials = New-Object System.Management.Automation.PSCredential ($asmLogin, (ConvertTo-SecureString $asmPassword -AsPlainText -Force))

$exports = @{}

$exports.Add($asmRostersScope, (New-Object System.Collections.Generic.List[System.Object]))

####### Functions to generate student and staff list #######
function generateASMFileForUsers($searchbases, $asmScope) {

    if (-not ($exports.Contains($asmScope))) {
        $exports.Add($asmScope, (New-Object System.Collections.Generic.List[System.Object]))
    }

    ForEach($base in $searchbases) {

        $users = Get-ADUser -Filter "*" -SearchBase "$base" -SearchScope Subtree
        
        ForEach($userDN in $users) {

            $adUser = Get-ADUser -Identity "$userDN" -Properties $userIDField,GivenName,Surname,Department,EmailAddress,$usernameField
            $userID = $adUser.$userIDField
            $userObject = New-Object System.Object
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "person_id" -Value $userID
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "first_name" -Value $adUser.GivenName
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "last_name" -Value $adUser.Surname

            $importUser = $false

            if ("$asmScope" -eq $asmStudentScope) {
                Add-Member -InputObject $userObject -MemberType NoteProperty -Name "grade_level" -Value $adUser.Department
                Add-Member -InputObject $userObject -MemberType NoteProperty -Name "password_policy" -Value "6"
                
                $relatedClasses = $allClassesID | Where {$_ -match ".*$($adUser.Department)" } 

                ForEach($classID in $relatedClasses) {
                    $rosterObject = New-Object System.Object
                    Add-Member -InputObject $rosterObject -MemberType NoteProperty -Name "roster_id" -Value "$userID-$classID"
                    Add-Member -InputObject $rosterObject -MemberType NoteProperty -Name "class_id" -Value $classID
                    Add-Member -InputObject $rosterObject -MemberType NoteProperty -Name "student_id" -Value $userID
                    $exports[$asmRostersScope].Add($rosterObject)
                }

                if ($adUser.Department -match "^02" -or $adUser.Department -match "^01" -or $adUser.Department -match "^00[ELST]") {
                    $className = $adUser.Department
                    Write-Debug "Inport user with class $className" 
                    $importUser = $true
                }
            } else {
                $importUser = $true
            }

            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "email_address" -Value $adUser.EmailAddress
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "sis_username" -Value $adUser.$usernameField
            
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "location_id" -Value "Campus"
            
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "person_number" -Value ""
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "middle_name" -Value ""
            
            if ($importUser) {
                $exports[$asmScope].Add($userObject)
            }

        }
          
    }

}


####### Function to convert array of hastables to CSV ready list #######
function convertArrayOfHastables($arrayOfHashtables, $asmScope) {

    if (-not ($exports.Contains($asmScope))) {
        $exports.Add($asmScope, (New-Object System.Collections.Generic.List[System.Object]))
    }

    ForEach($hastable in $arrayOfHashtables) {

            $object = New-Object System.Object

            ForEach($key in $hastable.Keys) {
                Add-Member -InputObject $object -MemberType NoteProperty -Name $key -Value $hastable[$key]
            }

            $exports[$asmScope].Add($object)
        }
}

####### Function to export scope to CSV #######
function exportScopeToCSV($asmScope) {
    $exports[$asmScope] | export-csv -Path "$workingFolder\tmp\$asmScope.tmp" -NoTypeInformation -encoding "unicode"

    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    $content = get-content "$workingFolder\tmp\$asmScope.tmp"
    [System.IO.File]::WriteAllLines("$workingFolder\csv\$asmScope.csv", $content, $Utf8NoBomEncoding)
}

####### Function to prepare export from CSV #######
function convertCSV($importedCSV, $mapping, $asmScope, $uniqueKey) {

    if (-not ($exports.Contains($asmScope))) {
        $exports.Add($asmScope, (New-Object System.Collections.Generic.List[System.Object]))
    }

    $existingKeys = New-Object System.Collections.Generic.List[System.Object]

    ForEach($item in $importedCSV) {
        
        $object = New-Object System.Object
        ForEach($asmKey in $mapping.Keys) {
            $keysToMap = $mapping[$asmKey]
            $finalValue = ""

            if ($keysToMap -is [system.array]) {
                ForEach($key in $keysToMap) {
                    $finalValue += $item.$key
                    $finalValue += " "
                }

                $finalValue = $finalValue.Trim()
            } else {
                $finalValue = $item.$keysToMap
            }

            Add-Member -InputObject $object -MemberType NoteProperty -Name $asmKey -Value $finalValue
        }
        
        Add-Member -InputObject $object -MemberType NoteProperty -Name "location_id" -Value "Campus"

        if ( -not ($existingKeys.Contains($object.$uniqueKey))) {
            $existingKeys.Add($object.$uniqueKey)
            $exports[$asmScope].Add($object)
        }
    }
}

####### Generate CSV for Locations #######
convertArrayOfHastables $asmLocations $asmLocationScope

####### Generate CSV for Courses #######
convertCSV $asmExportedCourses $asmCoursesMapping $asmCoursesScope $asmCoursesUniqueKey

####### Generate CSV for Classes #######
convertCSV $asmExportedClasses $asmClassesMapping $asmClassesScope $asmClassesUniqueKey
ForEach($class in $exports[$asmClassesScope]) {
    $allClassesID.Add($class.$asmClassesUniqueKey)
}

####### Generate CSV for Students #######
generateASMFileForUsers $searchBasesByScope[$asmStudentScope] $asmStudentScope

####### Generate CSV for Staff #######
generateASMFileForUsers $searchBasesByScope[$asmStaffScope] $asmStaffScope


####### Generate all available CSV #######
ForEach($asmScope in $exports.Keys) {
    exportScopeToCSV $asmScope
}

####### Manage dry run if needed #######

if ($dryRun) {
    Write-Host "CSV files created. It's a dry run so no upload to Apple School Manager."
    Write-Host "$workingFolder"
    ii "$workingFolder"
    exit 0
}

####### Generate ZIP archive #######
[io.compression.zipfile]::CreateFromDirectory("$workingFolder\csv", $finalArchive) 

####### Configure SFTP session to be dropbox compatible #######
$asmSession = New-WinSCPSession -HostName $asmServer -Credential $asmCredentials -Protocol Sftp -SshHostKeyFingerprint $asmServerPublicKey
$asmTransferResumeSupport = New-Object -TypeName WinSCP.TransferResumeSupport
$asmTransferResumeSupport.State = [WinSCP.TransferResumeSupportState]::Off
$asmTransferOptions = New-Object -TypeName WinSCP.TransferOptions
$asmTransferOptions.ResumeSupport = $asmTransferResumeSupport
$asmTransferOptions.PreserveTimestamp = $false

####### Send archive to Apple #######
Send-WinSCPItem -WinSCPSession $asmSession -Path $finalArchive -TransferOptions $asmTransferOptions -Destination "/dropbox" -Remove

####### Housekeeping #######
Remove-WinSCPSession -WinSCPSession $asmSession

if ($clearFiles) {
    Remove-Item -Path "$workingFolder" -Recurse
}

exit 0