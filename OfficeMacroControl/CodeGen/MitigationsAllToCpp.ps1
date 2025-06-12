$fname = ".\Mitigations-All.txt"

$headers = (Get-Content -Path $fname)[0].Split("`t")
$info = Import-Csv -Delimiter "`t" -Path $fname

$gpoNames = @(
    for ($ix = 5; $ix -lt $headers.Count; $ix += 3)
    {
        $headers[$ix]
    }
)

$crlf = "`r`n"
$ind = "    "
$secbreak = "// ------------------------------------------------------------------------------------------"

function ToVarName([string]$prefix, [string]$sInput)
{
    $retval = $prefix + $sInput.Replace("\", "").Replace(" ", "").Replace("-", "_").Replace(".", "").Replace("(", "").Replace(")", "").Replace(":", "").Replace(">", "").Replace("`t", "").Replace(",", "").Replace("/", "")
    Write-Output $retval
}

# Define string constants
$hGpPaths = @{}
$hGpNames = @{}
$hKeys = @{}
$hValNames = @{}
foreach ($polItem in $info)
{
    # Remove trailing backslash from GP Path
    $polItem.GpPath = $polItem.GpPath.TrimEnd("\")
    if (-not $hGpPaths.ContainsKey($polItem.GpPath))
    {
        $k = $polItem.GpPath
        $v = ToVarName -prefix "szGpPath_" -sInput $k
        $hGpPaths.Add($k, $v)
    }
    if (-not $hGpNames.ContainsKey($polItem.GpName))
    {
        $k = $polItem.GpName
        $v = ToVarName -prefix "szGpName_" -sInput $k
        $hGpNames.Add($k, $v)
    }
    if (-not $hKeys.ContainsKey($polItem.RegKey))
    {
        $k = $polItem.RegKey
        $v = ToVarName -prefix "szRegKey_" -sInput $k
        $hKeys.Add($k, $v)
    }
    if (-not $hValNames.ContainsKey($polItem.RegName))
    {
        $k = $polItem.RegName
        $v = ToVarName -prefix "szRegVal_" -sInput $k
        $hValNames.Add($k, $v)
    }
}

Write-Output $secbreak
Write-Output "// Define string constants"
Write-Output ""
$hGpPaths.Keys | Sort-Object | %{
    Write-Output ("const wchar_t* const " + $hGpPaths[$_] + " = " + "L`"" + $_.Replace("\", "\\") + "`";")
}
Write-Output ""
$hGpNames.Keys | Sort-Object | %{
    Write-Output ("const wchar_t* const " + $hGpNames[$_] + " = " + "L`"" + $_.Replace("\", "\\") + "`";")
}
Write-Output ""
$hKeys.Keys  | Sort-Object | %{
    Write-Output ("const wchar_t* const " + $hKeys[$_] + " = " + "L`"" + $_.Replace("\", "\\") + "`";")
}
Write-Output ""
$hValNames.Keys | Sort-Object | %{
    Write-Output ("const wchar_t* const " + $hValNames[$_] + " = " + "L`"" + $_.Replace("\", "\\") + "`";")
}
Write-Output ""

[System.Collections.ArrayList]$gpoBasenames = @()
[System.Collections.ArrayList]$gpoItems = @()

foreach ($polItem in $info)
{
    foreach ($gpoName in $gpoNames)
    {
        if ($polItem.$gpoName.Length -gt 0)
        {
            $ix = $gpoName.IndexOf("-")
            if ($ix -lt 0)
            {
                $basename = $gpoName
            }
            else
            {
                $basename = $gpoName.Substring(0, $ix)
            }
            if (-not $gpoBasenames.Contains($basename))
            {
                [void]$gpoBasenames.Add($basename)
            }
            Add-Member -InputObject $polItem -Name "GPO" -Value $basename -MemberType NoteProperty
            break
        }
    }
}

foreach ($polName in $gpoBasenames)
{
    $hPolDefns = @{}
    $hPolChoice = @{}
    $nIxDefn = 1
    [System.Collections.ArrayList]$settingDefs = @()
    [System.Collections.ArrayList]$choiceDefs = @()

    # Define setting definitions and item choices for this group of settings
    $info | ?{ $_.GPO -eq $polName } | %{
        $polItem = $_

        $sKey = $polItem.GpPath + $polItem.GpName + $polItem.RegKey + $polItem.RegName
        if (-not $hPolDefns.ContainsKey($sKey))
        {
            $varname = ToVarName -prefix "" -sInput ($polName + "_" + $nIxDefn++ + "_" + $polItem.RegName)
            $hPolDefns.Add($sKey, $varname)
            $line = "const GpoDefn_t " + $varname + " = { " + $crlf +
                $ind + $polItem.IsMachine + ", " + $crlf +
                $ind + $hGpPaths[$polItem.GpPath] + "," + $crlf +
                $ind + $hGpNames[$polItem.GpName] + "," + $crlf +
                $ind + $hKeys[$polItem.RegKey] + "," + $crlf +
                $ind + $hValNames[$polItem.RegName] + #", " + $crlf +
                # $ind +         $polItem.RegType + $crlf +
                " };"
            [void]$settingDefs.Add($line.Replace('\', '\\'))
        }

        foreach ($gpoName in $gpoNames)
        {
            if ($polItem.$gpoName.Length -gt 0)
            {
                $optProp = $gpoName + "||Option"
                $typeProp = $gpoName + "||Type"
                $optName = $polItem.$optProp
                $optType = $polItem.$typeProp
                $optVal = $polItem.$gpoName
                $sKey = $optName + $optVal
                if (-not $hPolChoice.ContainsKey($sKey))
                {
                    $varname = ToVarName -prefix "" -sInput ($polName + "_choice_" + $optName)
                    $hPolChoice.Add($sKey, $varname)
                    $line = "const GpoItemChoice_t " + $varname + " = { L`"" + $optName + "`", " + $optType + ", " + $optVal + " };"
                    [void]$choiceDefs.Add($line.Replace("\", "\\"))
                }
            }
        }
    }

    Write-Output $secbreak
    Write-Output ("// " + $polName + " - setting definitions")
    Write-Output ""
    Write-Output $settingDefs
    Write-Output ""
    Write-Output ("// " + $polName + " - choice definitions")
    Write-Output ""
    Write-Output $choiceDefs
    Write-Output ""

    # Define all the GPO collections
    foreach ($gpoName in $gpoNames)
    {
        if ($gpoName.StartsWith($polName))
        {
            [void]$gpoItems.Add("// " + $gpoName)
            [void]$gpoItems.Add("")
            $gpoVarname = ToVarName -prefix "" -sInput $gpoName
            [void]$gpoItems.Add("const GpoItem_t " + $gpoVarname + "[] = {")
            $info | ?{ $_.$gpoName.Length -gt 0 } | %{
                $polItem = $_
                $settingKey = $polItem.GpPath + $polItem.GpName + $polItem.RegKey + $polItem.RegName
                $optProp = $gpoName + "||Option"
                $typeProp = $gpoName + "||Type"
                $optName = $polItem.$optProp
                $optType = $polItem.$typeProp
                $optVal = $polItem.$gpoName
                $choiceKey = $optName + $optVal
                [void]$gpoItems.Add("    { " + $hPolDefns[$settingKey] + ", " + $hPolChoice[$choiceKey] + " },")
            }
            [void]$gpoItems.Add("    { NULL_GpoDefn, NULL_GpoItemChoice } };")
            #[void]$gpoItems.Add("};")
            #[void]$gpoItems.Add("const size_t n" + $gpoVarname + " = (sizeof(" + $gpoVarname + ") / sizeof(" + $gpoVarname + "[0])) - 1;")
            [void]$gpoItems.Add("")
        }
    }

}

Write-Output $secbreak
Write-Output @"

// Null defs to end arrays
const GpoDefn_t NULL_GpoDefn = {
    false,
    NULL,
    NULL,
    NULL,
    NULL };

const GpoItemChoice_t NULL_GpoItemChoice = { NULL, REG_NONE, 0 };

"@



Write-Output $secbreak
Write-Output $gpoItems

Write-Output ""
Write-Output $secbreak
Write-Output ""

[System.Collections.ArrayList]$arraydecl = @()
#[System.Collections.ArrayList]$sizedecl = @()
foreach ($gpoName in $gpoNames)
{
    $varname = ToVarName -prefix "" -sInput $gpoName
    [void]$arraydecl.Add("extern const GpoItem_t " + $varname + "[];")
    #[void]$sizedecl.Add("extern const size_t n" + $varname + ";")
}
Write-Output $arraydecl
#Write-Output $sizedecl

