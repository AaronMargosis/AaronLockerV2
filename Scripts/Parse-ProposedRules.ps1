<#
.SYNOPSIS
AaronLocker V2 proposed-rule-file parser.
Outputs a hash table from the contents of the named AaronLocker proposed-rule file.
Attributes include:

  TODO: define
    ProposedPathRules
    Proposed
    ComputerName
    ScanStarted
    ScanEnded
    ScanDuration
    WindowsDirectories
    ErrorInfo
    UnsafeDirsUnderWindows
    UnsafeDirsUnderPF
    SafePaths
    FileDetails
    AppLabels
    PackagedApps
    ShellLinks
#>

[CmdletBinding()]
param(
    [parameter(Mandatory=$true)]
    [String]
    $proposedRulefile
)

Set-Variable -Option Constant -Name HdrRuleBuilderOptions     -Value ":::: RULE BUILDER OPTIONS"
Set-Variable -Option Constant -Name HdrProposedPathRules      -Value ":::: PROPOSED PATH RULES"
Set-Variable -Option Constant -Name HdrProposedPublisherRules -Value ":::: PROPOSED PUBLISHER RULES"
Set-Variable -Option Constant -Name HdrProposedHashRules      -Value ":::: PROPOSED HASH RULES"

Set-Variable -Option Constant -Name CollectionExe    -Value "Exe"
Set-Variable -Option Constant -Name CollectionDll    -Value "Dll"
Set-Variable -Option Constant -Name CollectionMsi    -Value "Msi"
Set-Variable -Option Constant -Name CollectionScript -Value "Script"
Set-Variable -Option Constant -Name CollectionAppx   -Value "Appx"

$result = @{
    RuleBuilderOptions = $null;
    AllProposedPathRules = $null;
    AllProposedPublisherRules = $null;
    AllProposedHashRules = $null;
    AppxRules = $null;
    NonAppxPublisherRules = $null;
    RuleSetNames = $null;
    RuleSets = [System.Collections.ArrayList]@();
}

$lines = Get-Content $proposedRulefile
$ixCurr = 0
while( $ixCurr -lt $lines.Length )
{
    $line = $lines[$ixCurr++]

    if ($line -eq $HdrRuleBuilderOptions)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        # Picking up just the first line; there shouldn't be more than one.
        $result.RuleBuilderOptions = $lines[$ixBlockStart].Trim()
        $ixCurr++
    }
    elseif ($line -eq $HdrProposedPathRules)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.AllProposedPathRules = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrProposedPublisherRules)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.AllProposedPublisherRules = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrProposedHashRules)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.AllProposedHashRules = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
}

$result.NonAppxPublisherRules = @($result.AllProposedPublisherRules) | ?{ $_.Collection -ne $CollectionAppx }
$result.AppxRules = @($result.AllProposedPublisherRules) | ?{ $_.Collection -eq $CollectionAppx } | Select-Object Name, Description, Publisher, Product

$result.RuleSetNames =
    @($result.AllProposedPathRules.RuleSetName) + 
    @($result.NonAppxPublisherRules.RuleSetName) + 
    @($result.AllProposedHashRules.RuleSetName) | 
    Sort-Object -Unique

#Create an array of rule sets, where each rule set consists of a name and rules, where rules contains path, publisher, and hash rules
# Or a hash table keyed on rule set name
foreach ($ruleSetName in $result.RuleSetNames)
{
    $ruleSet = @{
        Name = $ruleSetName;
        Rules = @{
            PathRules      = $result.AllProposedPathRules | ?{ $_.Name -eq $ruleSetName };
            PublisherRules = $result.NonAppxPublisherRules | ?{ $_.Name -eq $ruleSetName };
            HashRules      = $result.AllProposedHashRules | ?{ $_.Name -eq $ruleSetName };
        }
    }
    [void]$result.RuleSets.Add($ruleSet)
}

Write-Output $result
