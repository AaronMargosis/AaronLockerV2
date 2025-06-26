<#
.SYNOPSIS
Generate C++ to list the GPO keys to clean up if they are empty, sorting in the order they need to be cleaned.
#>

$Machine = @'
Software\Policies\Microsoft\Windows
Software\Policies\Microsoft\Windows Defender\Real-Time Protection
Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR
Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules
'@

$User = @'
software\policies\microsoft\office\16.0\access\security
software\policies\microsoft\office\16.0\access\security\trusted locations
software\policies\microsoft\office\16.0\excel\security
software\policies\microsoft\office\16.0\excel\security\fileblock
software\policies\microsoft\office\16.0\excel\security\trusted locations
software\policies\microsoft\office\16.0\ms project\security
software\policies\microsoft\office\16.0\ms project\security\trusted locations
software\policies\microsoft\office\16.0\powerpoint\security
software\policies\microsoft\office\16.0\powerpoint\security\fileblock
software\policies\microsoft\office\16.0\powerpoint\security\trusted locations
software\policies\microsoft\office\16.0\publisher\security
software\policies\microsoft\office\16.0\visio\security
software\policies\microsoft\office\16.0\visio\security\fileblock
software\policies\microsoft\office\16.0\visio\security\trusted locations
software\policies\microsoft\office\16.0\word\security
software\policies\microsoft\office\16.0\word\security\fileblock
software\policies\microsoft\office\16.0\word\security\trusted locations
'@


function PartitionThem($sPath)
{
    $parts = $sPath.Split("\")
    $nParts = $parts.Count
    1..$nParts | %{ (0.. ($_ - 1) | %{ $parts[$_] }) -join "\\" }
}

function DoEach($sPaths)
{
    $sPaths.Split("`n").Trim() | %{ PartitionThem -sPath $_ } | sort -Descending -Unique | %{ Write-Output ('    L"' + $_ + '",') }
    Write-Output "    nullptr"
}

"// Machine paths:"
"const wchar_t* MachineKeysToCleanUp[] = {"
DoEach -sPaths $Machine
"};"
""
"// User paths:"
"const wchar_t* UserKeysToCleanUp[] = {"
DoEach -sPaths $User
"};"
""


