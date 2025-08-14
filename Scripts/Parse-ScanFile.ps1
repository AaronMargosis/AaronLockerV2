<#
.SYNOPSIS
AaronLocker V2 scan-file parser.
Outputs a hash table from the contents of the named AaronLocker scan file.
Attributes include:
    ScanType
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
    $scanfile
)

Set-Variable -Option Constant -Name HdrScanType           -Value ":::: SCAN TYPE: "
Set-Variable -Option Constant -Name HdrCompName           -Value ":::: COMPUTER NAME: "
Set-Variable -Option Constant -Name HdrScanStarted        -Value ":::: SCAN STARTED: "
Set-Variable -Option Constant -Name HdrScanEnded          -Value ":::: SCAN ENDED  : "
Set-Variable -Option Constant -Name HdrWindowsDirs        -Value ":::: WINDOWS DIRECTORIES:"
Set-Variable -Option Constant -Name HdrErrorInfo          -Value ":::: ERROR INFO:"
Set-Variable -Option Constant -Name HdrUnsafeUnderWindows -Value ":::: UNSAFE DIRECTORIES UNDER WINDOWS:"
Set-Variable -Option Constant -Name HdrUnsafeUnderPF      -Value ":::: UNSAFE DIRECTORIES UNDER PROGRAM FILES:"
Set-Variable -Option Constant -Name HdrSafePaths          -Value ":::: PLATFORM SAFE PATH INFO:"
Set-Variable -Option Constant -Name HdrFileDetails        -Value ":::: FILE DETAILS:"
Set-Variable -Option Constant -Name HdrPackagedApps       -Value ":::: INSTALLED PACKAGED APPS:"
Set-Variable -Option Constant -Name HdrShellLinks         -Value ":::: SHELL LINKS:"

$result = @{
    ScanType = $null;
    ComputerName = $null;
    ScanStarted = $null;
    ScanEnded = $null;
    ScanDuration = $null;
    WindowsDirectories = $null;
    ErrorInfo = $null;
    UnsafeDirsUnderWindows = $null;
    UnsafeDirsUnderPF = $null;
    SafePaths = $null;
    FileDetails = $null;
    AppLabels = $null;
    PackagedApps = $nulll;
    ShellLinks = $null;
}

$lines = Get-Content $scanfile
$ixCurr = 0
while( $ixCurr -lt $lines.Length )
{
    $line = $lines[$ixCurr++]

    if ($line.StartsWith($HdrScanType))
    {
        $result.ScanType = $line.Substring($HdrScanType.Length)
    }
    elseif ($line.StartsWith($HdrCompName))
    {
        $result.ComputerName = $line.Substring($HdrCompName.Length)
    }
    elseif ($line.StartsWith($HdrScanStarted))
    {
        $result.ScanStarted = [datetime]($line.Substring($HdrScanStarted.Length))
    }
    elseif ($line.StartsWith($HdrScanEnded))
    {
        $result.ScanEnded = [datetime]($line.Substring($HdrScanEnded.Length))
    }
    elseif ($line -eq $HdrWindowsDirs)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.WindowsDirectories = $lines[$ixBlockStart .. ($ixCurr-1)]
        $ixCurr++
    }
    elseif ($line -eq $HdrErrorInfo)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        if ($ixCurr -gt $ixBlockStart)
        {
            $result.ErrorInfo = $lines[$ixBlockStart .. ($ixCurr-1)]
        }
        $ixCurr++
    }
    elseif ($line -eq $HdrUnsafeUnderWindows)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.UnsafeDirsUnderWindows = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrUnsafeUnderPF)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.UnsafeDirsUnderPF = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrSafePaths)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.SafePaths = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrFileDetails)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.FileDetails = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrPackagedApps)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.PackagedApps = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
    elseif ($line -eq $HdrShellLinks)
    {
        $ixBlockStart = $ixCurr
        while ($lines[$ixCurr].Length -gt 0) { $ixCurr++ }
        $result.ShellLinks = $lines[$ixBlockStart .. $ixCurr] | ConvertFrom-Csv -Delimiter "`t"
        $ixCurr++
    }
}

if ($null -ne $result.ScanStarted -and $null -ne $result.ScanEnded)
{
    $result.ScanDuration = $result.ScanEnded - $result.ScanStarted
}
if ($null -ne $result.FileDetails)
{
    $result.AppLabels = $result.FileDetails.AppLabel | sort -Unique
}

Write-Output $result
