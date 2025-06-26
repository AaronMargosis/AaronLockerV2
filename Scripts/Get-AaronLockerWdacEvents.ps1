<#
.SYNOPSIS
Get-WdacEvents
#>

<#
# Template info about the events we want data about:
$evInfo = (Get-WinEvent -ListProvider "Microsoft-Windows-CodeIntegrity").Events | ?{ $_.Id -in @(3033, 3077, 3089) }
$evInfo | group Id | %{
    Write-Output ("Event ID " + $_.Name)
    $_.Group | %{
        "    Version:        " + $_.Version
        "    Description:    " + $_.Description
        "    Property count: " + (([xml]($_.Template)).template.data.Count)
        "    Template:"
        $_.Template.Split("`n") | %{ "                    " + $_.TrimEnd() }
    }
    ""
} | Out-File -Encoding utf8 .\CiEventsOfInterest-Win11-24H2.txt
#>

<#
function OutputEvInfo($ev)
{
    "    Event ID:       " + $ev.Id
    "    Version:        " + $ev.Version
    "    Description:    " + $ev.Description
    "    Property count: " + (([xml]($ev.Template)).template.data.Count)
    "    Template:"
    $ev.Template.Split("`n") | %{ "                    " + $_.TrimEnd() }
}

$evInfo = (Get-WinEvent -ListProvider "Microsoft-Windows-CodeIntegrity").Events | ?{ $_.Id -in @(3033, 3076, 3077, 3089) }
$evInfo | group Id | %{
    #Write-Output ("Event ID " + $_.Name)
    $_.Group | %{
        $fname = $_.Id.ToString() + "_" + $_.Version.ToString() + ".txt"
        OutputEvInfo -ev $_ | Out-File -Encoding utf8 $fname
    }
}
#>

<#
# 1 version of 3033
# 6 versions of 3077
$f3077 = @(gci 3077*.txt)
0..($f3077.Count - 2) | %{ windiff ("3077_" + $_ + ".txt") ("3077_" + ($_ + 1) + ".txt") }
$f3089 = @(gci 3089*.txt)
0..($f3089.Count - 2) | %{ windiff ("3089_" + $_ + ".txt") ("3089_" + ($_ + 1) + ".txt") }

# Compare 3076 versions to corresponding 3077 versions. Schema is the same for both
0..5 | %{ windiff ("3076_" + ($_) + ".txt") ("3077_" + ($_) + ".txt") }
#>

#$ev = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -FilterXPath '*[System[(EventID=3033 or EventID=3089 or EventID=3077)]]'

# Event ID 3077 is really all we need, and with all the versions, just get the Message text

$ev3077Info = @{}
(Get-WinEvent -ListProvider "Microsoft-Windows-CodeIntegrity").Events | Where-Object { $_.Id -eq 3077 } | %{ 

    $arrData = @(([xml]$_.Template).template.data)
    $propDictionary = @{}
    0 .. ($arrData.Count - 1) | %{ $propDictionary.Add( $arrData[$_].name, $_ ) }
    $ev3077Info.Add($_.Version.ToString(), $propDictionary)

}

<#
Known property names:
    File Name
    FileDescription
    FileDescriptionLength
    FileNameLength
    FileVersion
    InternalName
    InternalNameLength
    OriginalFileName
    OriginalFileNameLength
    PackageFamilyName
    PackageFamilyNameLength
    PolicyGUID
    PolicyHash
    PolicyHashSize
    PolicyID
    PolicyIDLength
    PolicyName
    PolicyNameLength
    Process Name
    ProcessNameLength
    ProductName
    ProductNameLength
    Requested Signing Level
    SHA1 Flat Hash
    SHA1 Flat Hash Size
    SHA1 Hash
    SHA1 Hash Size
    SHA256 Flat Hash
    SHA256 Flat Hash Size
    SHA256 Hash
    SHA256 Hash Size
    SI Signing Scenario
    Status
    UserWriteable
    USN
    Validated Signing Level

Data of interest:
    TimeCreated, UserID, Computer
    Need to get Version to interpret properties
    File Name
    Process Name
    PolicyName
    PolicyID
    PolicyGUID
#>

function GetTheEventData()
{
    $ev3077 = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath '*[System[(EventID=3076 or EventID=3077)]]')

    $headers = @(
        "Date/time",
        "Message",
        "UserId",
        "Computer",
        "Level",
        "Process Name", 
        "File Name", 
        "PolicyID", 
        "PolicyName", 
        "PolicyGUID") -join "`t"

    Write-Output $headers

    foreach ($ev in $ev3077) {

        $ver = $ev.Version.ToString()
        $dict = $ev3077Info[$ver]

        $evData1 = @(
            $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
            $ev.Message,
            $ev.UserId,
            $ev.MachineName,
            $ev.LevelDisplayName
        )

        $evData2 = 
            if ($null -ne $dict)
            {
                # Try to get these:
                @("Process Name", "File Name", "PolicyID", "PolicyName", "PolicyGUID") | %{
                    $ixProperty = $dict[$_]
                    if ($null -ne $ixProperty)
                    {
                        $ev.Properties[$ixProperty].Value
                    }
                    else
                    {
                        ""
                    }
                }
            }
            else
            {
                @("", "", "", "", "")
            }

        ($evData1 + $evData2) -join "`t"
    }
}

GetTheEventData | ConvertFrom-Csv -Delimiter "`t"
