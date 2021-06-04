function Import-ActiveDirectory
{
<#
.SYNOPSIS
ADModule Script which could import ActiveDirectory module without writing DLL to disk.

.DESCRIPTION
This script will import AD modules without writing DLL to disk. To use your own DLL byte array use the below commands:

PS > [byte[]] $DLL = Get-Content -Encoding byte -path C:\ADModule\Microsoft.ActiveDirectory.Management.dll
PS > [System.IO.File]::WriteAllLines(C:\ADModule\dll.txt, ([string]$DLL))

It is always advised to load your own DLL ;)

.PARAMETER ActiveDirectoryModule
Path to the ActiveDirectoryModule DLL.

.EXAMPLE
PS > Import-ActiveDirectory

Use the above command to load the DLL byte array already hard-coded in the script. 

.EXAMPLE
PS > Import-ActiveDirectory -ActiveDirectoryModule C:\ADModule\Microsoft.ActiveDirectory.Management.dll

Use the above path to load the Microsoft.ActiveDirectory.Management.dll from disk.

.LINK
https://github.com/samratashok/ADModule/pull/1
https://github.com/samratashok/ADModule
#>  

#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ActiveDirectoryModule
    )

    $retVal = Get-Module -ListAvailable | where { $_.Name -eq "ActiveDirectory" }
    if ($retVal) {
        Import-Module ActiveDirectory
    } else {
        if($ActiveDirectoryModule) {
            $path = Resolve-Path $ActiveDirectoryModule
            $DllBytes = [IO.File]::ReadAllBytes($path)
			$Assembly = [System.Reflection.Assembly]::Load($DllBytes)
            Import-Module -Assembly $Assembly
        } else {
            [Byte[]] $DllBytes = [Convert]::FromBase64String($Data)
			$ActiveDirectory_psd1 = "//5AAHsACgBHAFUASQBEAD0AIgB7ADQAMwBjADEANQA2ADMAMAAtADkANQA5AGMALQA0ADkAZQA0AC0AYQA5ADcANwAtADcANQA4AGMANQBjAGMAOQAzADQAMAA4AH0AIgAKAEEAdQB0AGgAbwByAD0AIgBNAGkAYwByAG8AcwBvAGYAdAAgAEMAbwByAHAAbwByAGEAdABpAG8AbgAiAAoAQwBvAG0AcABhAG4AeQBOAGEAbQBlAD0AIgBNAGkAYwByAG8AcwBvAGYAdAAgAEMAbwByAHAAbwByAGEAdABpAG8AbgAiAAoATQBvAGQAdQBsAGUAVgBlAHIAcwBpAG8AbgA9ACIAMQAuADAALgAxAC4AMAAiAAoAQwBvAG0AcABhAHQAaQBiAGwAZQBQAFMARQBkAGkAdABpAG8AbgBzACAAPQAgAEAAKAAnAEQAZQBzAGsAdABvAHAAJwAsACcAQwBvAHIAZQAnACkACgBQAG8AdwBlAHIAUwBoAGUAbABsAFYAZQByAHMAaQBvAG4APQAiADUALgAxACIACgBDAG8AcAB5AHIAaQBnAGgAdAA9ACIAqQAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AIABBAGwAbAAgAHIAaQBnAGgAdABzACAAcgBlAHMAZQByAHYAZQBkAC4AIgAKAE4AZQBzAHQAZQBkAE0AbwBkAHUAbABlAHMAPQAiAE0AaQBjAHIAbwBzAG8AZgB0AC4AQQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AZABsAGwAIgAKAFIAZQBxAHUAaQByAGUAZABBAHMAcwBlAG0AYgBsAGkAZQBzAD0AIgBNAGkAYwByAG8AcwBvAGYAdAAuAEEAYwB0AGkAdgBlAEQAaQByAGUAYwB0AG8AcgB5AC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAGQAbABsACIACgBUAHkAcABlAHMAVABvAFAAcgBvAGMAZQBzAHMAPQAiAEEAYwB0AGkAdgBlAEQAaQByAGUAYwB0AG8AcgB5AC4AVAB5AHAAZQBzAC4AcABzADEAeABtAGwAIgAKAEYAbwByAG0AYQB0AHMAVABvAFAAcgBvAGMAZQBzAHMAPQAiAEEAYwB0AGkAdgBlAEQAaQByAGUAYwB0AG8AcgB5AC4ARgBvAHIAbQBhAHQALgBwAHMAMQB4AG0AbAAiAAoASABlAGwAcABJAG4AZgBvAFUAcgBpAD0AIgBoAHQAdABwAHMAOgAvAC8AZwBvAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAGYAdwBsAGkAbgBrAC8APwBMAGkAbgBrAEkAZAA9ADMAOQAwADcANAAzACAAIgAKAEMAbQBkAGwAZQB0AHMAVABvAEUAeABwAG8AcgB0AD0ACgAgACAAIAAgACIAQQBkAGQALQBBAEQAQwBlAG4AdAByAGEAbABBAGMAYwBlAHMAcwBQAG8AbABpAGMAeQBNAGUAbQBiAGUAcgAiACwACgAgACAAIAAgACIAQQBkAGQALQBBAEQAQwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAQQBjAGMAbwB1AG4AdAAiACwACgAgACAAIAAgACIAQQBkAGQALQBBAEQARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBQAGEAcwBzAHcAbwByAGQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBBAGQAZAAtAEEARABGAGkAbgBlAEcAcgBhAGkAbgBlAGQAUABhAHMAcwB3AG8AcgBkAFAAbwBsAGkAYwB5AFMAdQBiAGoAZQBjAHQAIgAsAAoAIAAgACAAIAAiAEEAZABkAC0AQQBEAEcAcgBvAHUAcABNAGUAbQBiAGUAcgAiACwACgAgACAAIAAgACIAQQBkAGQALQBBAEQAUAByAGkAbgBjAGkAcABhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAHMAaABpAHAAIgAsAAoAIAAgACAAIAAiAEEAZABkAC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkATABpAHMAdABNAGUAbQBiAGUAcgAiACwACgAgACAAIAAgACIAQwBsAGUAYQByAC0AQQBEAEEAYwBjAG8AdQBuAHQARQB4AHAAaQByAGEAdABpAG8AbgAiACwACgAgACAAIAAgACIAQwBsAGUAYQByAC0AQQBEAEMAbABhAGkAbQBUAHIAYQBuAHMAZgBvAHIAbQBMAGkAbgBrACIALAAKACAAIAAgACAAIgBEAGkAcwBhAGIAbABlAC0AQQBEAEEAYwBjAG8AdQBuAHQAIgAsAAoAIAAgACAAIAAiAEQAaQBzAGEAYgBsAGUALQBBAEQATwBwAHQAaQBvAG4AYQBsAEYAZQBhAHQAdQByAGUAIgAsAAoAIAAgACAAIAAiAEUAbgBhAGIAbABlAC0AQQBEAEEAYwBjAG8AdQBuAHQAIgAsAAoAIAAgACAAIAAiAEUAbgBhAGIAbABlAC0AQQBEAE8AcAB0AGkAbwBuAGEAbABGAGUAYQB0AHUAcgBlACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABBAGMAYwBvAHUAbgB0AEEAdQB0AGgAbwByAGkAegBhAHQAaQBvAG4ARwByAG8AdQBwACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABBAGMAYwBvAHUAbgB0AFIAZQBzAHUAbAB0AGEAbgB0AFAAYQBzAHMAdwBvAHIAZABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5AFMAaQBsAG8AIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEMAZQBuAHQAcgBhAGwAQQBjAGMAZQBzAHMAUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEMAZQBuAHQAcgBhAGwAQQBjAGMAZQBzAHMAUgB1AGwAZQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAQwBsAGEAaQBtAFQAcgBhAG4AcwBmAG8AcgBtAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABDAGwAYQBpAG0AVAB5AHAAZQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAQwBvAG0AcAB1AHQAZQByACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABDAG8AbQBwAHUAdABlAHIAUwBlAHIAdgBpAGMAZQBBAGMAYwBvAHUAbgB0ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABEAEMAQwBsAG8AbgBpAG4AZwBFAHgAYwBsAHUAZABlAGQAQQBwAHAAbABpAGMAYQB0AGkAbwBuAEwAaQBzAHQAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEQAZQBmAGEAdQBsAHQARABvAG0AYQBpAG4AUABhAHMAcwB3AG8AcgBkAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABEAG8AbQBhAGkAbgAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBQAGEAcwBzAHcAbwByAGQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQByAFAAYQBzAHMAdwBvAHIAZABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAVQBzAGEAZwBlACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABGAGkAbgBlAEcAcgBhAGkAbgBlAGQAUABhAHMAcwB3AG8AcgBkAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABGAGkAbgBlAEcAcgBhAGkAbgBlAGQAUABhAHMAcwB3AG8AcgBkAFAAbwBsAGkAYwB5AFMAdQBiAGoAZQBjAHQAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEYAbwByAGUAcwB0ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABHAHIAbwB1AHAAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAEcAcgBvAHUAcABNAGUAbQBiAGUAcgAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQATwBiAGoAZQBjAHQAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAE8AcAB0AGkAbwBuAGEAbABGAGUAYQB0AHUAcgBlACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABPAHIAZwBhAG4AaQB6AGEAdABpAG8AbgBhAGwAVQBuAGkAdAAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAUAByAGkAbgBjAGkAcABhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAHMAaABpAHAAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBBAHQAdAByAGkAYgB1AHQAZQBNAGUAdABhAGQAYQB0AGEAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBDAG8AbgBuAGUAYwB0AGkAbwBuACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4ARgBhAGkAbAB1AHIAZQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFAAYQByAHQAbgBlAHIATQBlAHQAYQBkAGEAdABhACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUQB1AGUAdQBlAE8AcABlAHIAYQB0AGkAbwBuACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwBpAHQAZQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFMAaQB0AGUATABpAG4AawAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFMAaQB0AGUATABpAG4AawBCAHIAaQBkAGcAZQAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFMAdQBiAG4AZQB0ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AVQBwAFQAbwBEAGEAdABlAG4AZQBzAHMAVgBlAGMAdABvAHIAVABhAGIAbABlACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcwBvAHUAcgBjAGUAUAByAG8AcABlAHIAdAB5ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABSAGUAcwBvAHUAcgBjAGUAUAByAG8AcABlAHIAdAB5AEwAaQBzAHQAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkAVgBhAGwAdQBlAFQAeQBwAGUAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAFIAbwBvAHQARABTAEUAIgAsAAoAIAAgACAAIAAiAEcAZQB0AC0AQQBEAFMAZQByAHYAaQBjAGUAQQBjAGMAbwB1AG4AdAAiACwACgAgACAAIAAgACIARwBlAHQALQBBAEQAVAByAHUAcwB0ACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABVAHMAZQByACIALAAKACAAIAAgACAAIgBHAGUAdAAtAEEARABVAHMAZQByAFIAZQBzAHUAbAB0AGEAbgB0AFAAYQBzAHMAdwBvAHIAZABQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIARwByAGEAbgB0AC0AQQBEAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAG8AbABpAGMAeQBTAGkAbABvAEEAYwBjAGUAcwBzACIALAAKACAAIAAgACAAIgBJAG4AcwB0AGEAbABsAC0AQQBEAFMAZQByAHYAaQBjAGUAQQBjAGMAbwB1AG4AdAAiACwACgAgACAAIAAgACIATQBvAHYAZQAtAEEARABEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGUAcgAiACwACgAgACAAIAAgACIATQBvAHYAZQAtAEEARABEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGUAcgBPAHAAZQByAGEAdABpAG8AbgBNAGEAcwB0AGUAcgBSAG8AbABlACIALAAKACAAIAAgACAAIgBNAG8AdgBlAC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAG8AbABpAGMAeQBTAGkAbABvACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABDAGUAbgB0AHIAYQBsAEEAYwBjAGUAcwBzAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABDAGUAbgB0AHIAYQBsAEEAYwBjAGUAcwBzAFIAdQBsAGUAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAEMAbABhAGkAbQBUAHIAYQBuAHMAZgBvAHIAbQBQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIATgBlAHcALQBBAEQAQwBsAGEAaQBtAFQAeQBwAGUAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAEMAbwBtAHAAdQB0AGUAcgAiACwACgAgACAAIAAgACIATgBlAHcALQBBAEQARABDAEMAbABvAG4AZQBDAG8AbgBmAGkAZwBGAGkAbABlACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABGAGkAbgBlAEcAcgBhAGkAbgBlAGQAUABhAHMAcwB3AG8AcgBkAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABHAHIAbwB1AHAAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABPAHIAZwBhAG4AaQB6AGEAdABpAG8AbgBhAGwAVQBuAGkAdAAiACwACgAgACAAIAAgACIATgBlAHcALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAFMAaQB0AGUAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBTAGkAdABlAEwAaQBuAGsAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBTAGkAdABlAEwAaQBuAGsAQgByAGkAZABnAGUAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBTAHUAYgBuAGUAdAAiACwACgAgACAAIAAgACIATgBlAHcALQBBAEQAUgBlAHMAbwB1AHIAYwBlAFAAcgBvAHAAZQByAHQAeQAiACwACgAgACAAIAAgACIATgBlAHcALQBBAEQAUgBlAHMAbwB1AHIAYwBlAFAAcgBvAHAAZQByAHQAeQBMAGkAcwB0ACIALAAKACAAIAAgACAAIgBOAGUAdwAtAEEARABTAGUAcgB2AGkAYwBlAEEAYwBjAG8AdQBuAHQAIgAsAAoAIAAgACAAIAAiAE4AZQB3AC0AQQBEAFUAcwBlAHIAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5AFMAaQBsAG8AIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEMAZQBuAHQAcgBhAGwAQQBjAGMAZQBzAHMAUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEMAZQBuAHQAcgBhAGwAQQBjAGMAZQBzAHMAUABvAGwAaQBjAHkATQBlAG0AYgBlAHIAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEMAZQBuAHQAcgBhAGwAQQBjAGMAZQBzAHMAUgB1AGwAZQAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQAQwBsAGEAaQBtAFQAcgBhAG4AcwBmAG8AcgBtAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABDAGwAYQBpAG0AVAB5AHAAZQAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQAQwBvAG0AcAB1AHQAZQByACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABDAG8AbQBwAHUAdABlAHIAUwBlAHIAdgBpAGMAZQBBAGMAYwBvAHUAbgB0ACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQByAFAAYQBzAHMAdwBvAHIAZABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEYAaQBuAGUARwByAGEAaQBuAGUAZABQAGEAcwBzAHcAbwByAGQAUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAEYAaQBuAGUARwByAGEAaQBuAGUAZABQAGEAcwBzAHcAbwByAGQAUABvAGwAaQBjAHkAUwB1AGIAagBlAGMAdAAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQARwByAG8AdQBwACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABPAHIAZwBhAG4AaQB6AGEAdABpAG8AbgBhAGwAVQBuAGkAdAAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQAUAByAGkAbgBjAGkAcABhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAHMAaABpAHAAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBTAGkAdABlACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwBpAHQAZQBMAGkAbgBrACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwBpAHQAZQBMAGkAbgBrAEIAcgBpAGQAZwBlACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwB1AGIAbgBlAHQAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkATABpAHMAdAAiACwACgAgACAAIAAgACIAUgBlAG0AbwB2AGUALQBBAEQAUgBlAHMAbwB1AHIAYwBlAFAAcgBvAHAAZQByAHQAeQBMAGkAcwB0AE0AZQBtAGIAZQByACIALAAKACAAIAAgACAAIgBSAGUAbQBvAHYAZQAtAEEARABTAGUAcgB2AGkAYwBlAEEAYwBjAG8AdQBuAHQAIgAsAAoAIAAgACAAIAAiAFIAZQBtAG8AdgBlAC0AQQBEAFUAcwBlAHIAIgAsAAoAIAAgACAAIAAiAFIAZQBuAGEAbQBlAC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBSAGUAdgBvAGsAZQAtAEEARABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAUwBpAGwAbwBBAGMAYwBlAHMAcwAiACwACgAgACAAIAAgACIAUgBlAHMAZQB0AC0AQQBEAFMAZQByAHYAaQBjAGUAQQBjAGMAbwB1AG4AdABQAGEAcwBzAHcAbwByAGQAIgAsAAoAIAAgACAAIAAiAFIAZQBzAHQAbwByAGUALQBBAEQATwBiAGoAZQBjAHQAIgAsAAoAIAAgACAAIAAiAFMAZQBhAHIAYwBoAC0AQQBEAEEAYwBjAG8AdQBuAHQAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAEEAYwBjAG8AdQBuAHQAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5AFMAaQBsAG8AIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQQBjAGMAbwB1AG4AdABFAHgAcABpAHIAYQB0AGkAbwBuACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABBAGMAYwBvAHUAbgB0AFAAYQBzAHMAdwBvAHIAZAAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABvAGwAaQBjAHkAUwBpAGwAbwAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQwBlAG4AdAByAGEAbABBAGMAYwBlAHMAcwBQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQwBlAG4AdAByAGEAbABBAGMAYwBlAHMAcwBSAHUAbABlACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABDAGwAYQBpAG0AVAByAGEAbgBzAGYAbwByAG0ATABpAG4AawAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQwBsAGEAaQBtAFQAcgBhAG4AcwBmAG8AcgBtAFAAbwBsAGkAYwB5ACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABDAGwAYQBpAG0AVAB5AHAAZQAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAQwBvAG0AcAB1AHQAZQByACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABEAGUAZgBhAHUAbAB0AEQAbwBtAGEAaQBuAFAAYQBzAHMAdwBvAHIAZABQAG8AbABpAGMAeQAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQARABvAG0AYQBpAG4AIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAEQAbwBtAGEAaQBuAE0AbwBkAGUAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAEYAaQBuAGUARwByAGEAaQBuAGUAZABQAGEAcwBzAHcAbwByAGQAUABvAGwAaQBjAHkAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAEYAbwByAGUAcwB0ACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABGAG8AcgBlAHMAdABNAG8AZABlACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABHAHIAbwB1AHAAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABPAHIAZwBhAG4AaQB6AGEAdABpAG8AbgBhAGwAVQBuAGkAdAAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAUgBlAHAAbABpAGMAYQB0AGkAbwBuAEMAbwBuAG4AZQBjAHQAaQBvAG4AIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAFIAZQBwAGwAaQBjAGEAdABpAG8AbgBTAGkAdABlACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwBpAHQAZQBMAGkAbgBrACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwBpAHQAZQBMAGkAbgBrAEIAcgBpAGQAZwBlACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABSAGUAcABsAGkAYwBhAHQAaQBvAG4AUwB1AGIAbgBlAHQAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkAIgAsAAoAIAAgACAAIAAiAFMAZQB0AC0AQQBEAFIAZQBzAG8AdQByAGMAZQBQAHIAbwBwAGUAcgB0AHkATABpAHMAdAAiACwACgAgACAAIAAgACIAUwBlAHQALQBBAEQAUwBlAHIAdgBpAGMAZQBBAGMAYwBvAHUAbgB0ACIALAAKACAAIAAgACAAIgBTAGUAdAAtAEEARABVAHMAZQByACIALAAKACAAIAAgACAAIgBTAGgAbwB3AC0AQQBEAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAG8AbABpAGMAeQBFAHgAcAByAGUAcwBzAGkAbwBuACIALAAKACAAIAAgACAAIgBTAHkAbgBjAC0AQQBEAE8AYgBqAGUAYwB0ACIALAAKACAAIAAgACAAIgBUAGUAcwB0AC0AQQBEAFMAZQByAHYAaQBjAGUAQQBjAGMAbwB1AG4AdAAiACwACgAgACAAIAAgACIAVQBuAGkAbgBzAHQAYQBsAGwALQBBAEQAUwBlAHIAdgBpAGMAZQBBAGMAYwBvAHUAbgB0ACIALAAKACAAIAAgACAAIgBVAG4AbABvAGMAawAtAEEARABBAGMAYwBvAHUAbgB0ACIACgB9AAoA"
			$ActiveDirectory_Types_ps1xml = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+DQo8IS0tICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioNClRoaXMgZmlsZSBjb250YWlucyB0eXBlIGluZm9ybWF0aW9uIGZvciB0aGUgQWN0aXZlIERpcmVjdG9yeSBQb3dlclNoZWxsDQpTbmFwaW4uDQoNCkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLiAgQWxsIHJpZ2h0cyByZXNlcnZlZC4NCioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqIC0tPg0KPFR5cGVzPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHk8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRE9iamVjdDwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFET3JnYW5pemF0aW9uYWxVbml0PC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURQcmluY2lwYWw8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREdyb3VwPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURVc2VyPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURDb21wdXRlcjwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEQWNjb3VudDwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEU2VydmljZUFjY291bnQ8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRERvbWFpbjwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERmluZUdyYWluZWRQYXNzd29yZFBvbGljeTwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEUm9vdERTRTwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERGVmYXVsdERvbWFpblBhc3N3b3JkUG9saWN5PC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQUREaXJlY3RvcnlTZXJ2ZXI8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRERvbWFpbkNvbnRyb2xsZXI8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREZvcmVzdDwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFET3B0aW9uYWxGZWF0dXJlPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvblNpdGU8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRFJlcGxpY2F0aW9uU3VibmV0PC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvblNpdGVMaW5rPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvblNpdGVMaW5rQnJpZGdlPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvbkF0dHJpYnV0ZU1ldGFkYXRhPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvbkZhaWx1cmU8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRFJlcGxpY2F0aW9uUGFydG5lck1ldGFkYXRhPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvblF1ZXVlT3BlcmF0aW9uPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvblVwVG9EYXRlbmVzc1ZlY3RvclRhYmxlPC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURSZXBsaWNhdGlvbkNvbm5lY3Rpb248L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRENsYWltVHlwZUJhc2U8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRFJlc291cmNlUHJvcGVydHk8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRENsYWltVHlwZTwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEQ2VudHJhbEFjY2Vzc1BvbGljeTwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEQ2VudHJhbEFjY2Vzc1J1bGU8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRFJlc291cmNlUHJvcGVydHlMaXN0PC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgPFR5cGU+DQogICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEUmVzb3VyY2VQcm9wZXJ0eVZhbHVlVHlwZTwvTmFtZT4NCiAgICA8VHlwZUFkYXB0ZXI+DQogICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgPC9UeXBlQWRhcHRlcj4NCiAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURUcnVzdDwvTmFtZT4NCiAgICAgICAgPFR5cGVBZGFwdGVyPg0KICAgICAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREVudGl0eUFkYXB0ZXI8L1R5cGVOYW1lPg0KICAgICAgICA8L1R5cGVBZGFwdGVyPg0KICAgIDwvVHlwZT4NCiAgICA8VHlwZT4NCiAgICAgICAgPE5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFEQ2xhaW1UcmFuc2Zvcm1Qb2xpY3k8L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQogICAgPFR5cGU+DQogICAgICAgIDxOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BREF1dGhlbnRpY2F0aW9uUG9saWN5PC9OYW1lPg0KICAgICAgICA8VHlwZUFkYXB0ZXI+DQogICAgICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFERW50aXR5QWRhcHRlcjwvVHlwZU5hbWU+DQogICAgICAgIDwvVHlwZUFkYXB0ZXI+DQogICAgPC9UeXBlPg0KICAgIDxUeXBlPg0KICAgICAgICA8TmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURBdXRoZW50aWNhdGlvblBvbGljeVNpbG88L05hbWU+DQogICAgICAgIDxUeXBlQWRhcHRlcj4NCiAgICAgICAgICAgIDxUeXBlTmFtZT5NaWNyb3NvZnQuQWN0aXZlRGlyZWN0b3J5Lk1hbmFnZW1lbnQuQURFbnRpdHlBZGFwdGVyPC9UeXBlTmFtZT4NCiAgICAgICAgPC9UeXBlQWRhcHRlcj4NCiAgICA8L1R5cGU+DQo8L1R5cGVzPg=="
			$ActiveDirectory_Format_ps1xml = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+DQo8IS0tICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioNClRoaXMgZmlsZSBjb250YWlucyBmb3JtYXQgaW5mb3JtYXRpb24gZm9yIHRoZSBBY3RpdmUgRGlyZWN0b3J5IFBvd2VyU2hlbGwNClNuYXBpbi4NCg0KQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uICBBbGwgcmlnaHRzIHJlc2VydmVkLg0KKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogLS0+DQo8Q29uZmlndXJhdGlvbj4NCiAgPFZpZXdEZWZpbml0aW9ucz4NCiAgICA8Vmlldz4NCiAgICAgIDxOYW1lPkFET2JqZWN0PC9OYW1lPg0KICAgICAgPFZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFET2JqZWN0I1Byb3ZpZGVyWDUwMERlZmF1bHRQcm9wZXJ0eVNldDwvVHlwZU5hbWU+DQogICAgICA8L1ZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgPFRhYmxlQ29udHJvbD4NCiAgICAgICAgPFRhYmxlSGVhZGVycz4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+TmFtZTwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MjA8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+T2JqZWN0Q2xhc3M8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjIwPC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPkRpc3Rpbmd1aXNoZWROYW1lPC9MYWJlbD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgIDwvVGFibGVIZWFkZXJzPg0KICAgICAgICA8VGFibGVSb3dFbnRyaWVzPg0KICAgICAgICAgIDxUYWJsZVJvd0VudHJ5Pg0KICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbXM+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5OYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+T2JqZWN0Q2xhc3M8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5EaXN0aW5ndWlzaGVkTmFtZTwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtcz4NCiAgICAgICAgICA8L1RhYmxlUm93RW50cnk+DQogICAgICAgIDwvVGFibGVSb3dFbnRyaWVzPg0KICAgICAgPC9UYWJsZUNvbnRyb2w+DQogICAgPC9WaWV3Pg0KDQogICAgPFZpZXc+DQogICAgICA8TmFtZT5BRE9iamVjdDwvTmFtZT4NCiAgICAgIDxWaWV3U2VsZWN0ZWRCeT4NCiAgICAgICAgPFR5cGVOYW1lPk1pY3Jvc29mdC5BY3RpdmVEaXJlY3RvcnkuTWFuYWdlbWVudC5BRE9iamVjdCNQcm92aWRlclg1MDBEZWZhdWx0UHJvcGVydHlTZXQ8L1R5cGVOYW1lPg0KICAgICAgPC9WaWV3U2VsZWN0ZWRCeT4NCiAgICAgIDxMaXN0Q29udHJvbD4NCiAgICAgICAgPExpc3RFbnRyaWVzPg0KICAgICAgICAgIDxMaXN0RW50cnk+DQogICAgICAgICAgICA8TGlzdEl0ZW1zPg0KICAgICAgICAgICAgICA8TGlzdEl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5OYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvTGlzdEl0ZW0+DQogICAgICAgICAgICAgIDxMaXN0SXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPk9iamVjdENsYXNzPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvTGlzdEl0ZW0+DQogICAgICAgICAgICAgIDxMaXN0SXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPkRpc3Rpbmd1aXNoZWROYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvTGlzdEl0ZW0+DQogICAgICAgICAgICAgIDxMaXN0SXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPk9iamVjdEd1aWQ8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9MaXN0SXRlbT4NCiAgICAgICAgICAgIDwvTGlzdEl0ZW1zPg0KICAgICAgICAgIDwvTGlzdEVudHJ5Pg0KICAgICAgICA8L0xpc3RFbnRyaWVzPg0KICAgICAgPC9MaXN0Q29udHJvbD4NCiAgICA8L1ZpZXc+DQoNCiAgICA8Vmlldz4NCiAgICAgIDxOYW1lPkFET2JqZWN0PC9OYW1lPg0KICAgICAgPFZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFET2JqZWN0I1Byb3ZpZGVyQ2Fub25pY2FsRGVmYXVsdFByb3BlcnR5U2V0PC9UeXBlTmFtZT4NCiAgICAgIDwvVmlld1NlbGVjdGVkQnk+DQogICAgICA8VGFibGVDb250cm9sPg0KICAgICAgICA8VGFibGVIZWFkZXJzPg0KICAgICAgICAgIDxUYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICAgIDxMYWJlbD5OYW1lPC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD4yMDwvV2lkdGg+DQogICAgICAgICAgICA8QWxpZ25tZW50PmxlZnQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgIDxUYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICAgIDxMYWJlbD5PYmplY3RDbGFzczwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MjA8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RGlzdGluZ3Vpc2hlZE5hbWU8L0xhYmVsPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+Q2Fub25pY2FsTmFtZTwvTGFiZWw+DQogICAgICAgICAgICA8QWxpZ25tZW50PmxlZnQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICA8L1RhYmxlSGVhZGVycz4NCiAgICAgICAgPFRhYmxlUm93RW50cmllcz4NCiAgICAgICAgICA8VGFibGVSb3dFbnRyeT4NCiAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW1zPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+TmFtZTwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPk9iamVjdENsYXNzPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+RGlzdGluZ3Vpc2hlZE5hbWU8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5DYW5vbmljYWxOYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW1zPg0KICAgICAgICAgIDwvVGFibGVSb3dFbnRyeT4NCiAgICAgICAgPC9UYWJsZVJvd0VudHJpZXM+DQogICAgICA8L1RhYmxlQ29udHJvbD4NCiAgICA8L1ZpZXc+DQoNCiAgICA8Vmlldz4NCiAgICAgIDxOYW1lPkFET2JqZWN0PC9OYW1lPg0KICAgICAgPFZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgICA8VHlwZU5hbWU+TWljcm9zb2Z0LkFjdGl2ZURpcmVjdG9yeS5NYW5hZ2VtZW50LkFET2JqZWN0I1Byb3ZpZGVyQ2Fub25pY2FsRGVmYXVsdFByb3BlcnR5U2V0PC9UeXBlTmFtZT4NCiAgICAgIDwvVmlld1NlbGVjdGVkQnk+DQogICAgICA8TGlzdENvbnRyb2w+DQogICAgICAgIDxMaXN0RW50cmllcz4NCiAgICAgICAgICA8TGlzdEVudHJ5Pg0KICAgICAgICAgICAgPExpc3RJdGVtcz4NCiAgICAgICAgICAgICAgPExpc3RJdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+TmFtZTwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L0xpc3RJdGVtPg0KICAgICAgICAgICAgICA8TGlzdEl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5PYmplY3RDbGFzczwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L0xpc3RJdGVtPg0KICAgICAgICAgICAgICA8TGlzdEl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5EaXN0aW5ndWlzaGVkTmFtZTwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L0xpc3RJdGVtPg0KICAgICAgICAgICAgICA8TGlzdEl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5DYW5vbmljYWxOYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvTGlzdEl0ZW0+DQogICAgICAgICAgICAgIDxMaXN0SXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPk9iamVjdEd1aWQ8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9MaXN0SXRlbT4NCiAgICAgICAgICAgIDwvTGlzdEl0ZW1zPg0KICAgICAgICAgIDwvTGlzdEVudHJ5Pg0KICAgICAgICA8L0xpc3RFbnRyaWVzPg0KICAgICAgPC9MaXN0Q29udHJvbD4NCiAgICA8L1ZpZXc+DQogICAgDQogIDwvVmlld0RlZmluaXRpb25zPg0KPC9Db25maWd1cmF0aW9uPg=="
			$tmp = [io.path]::GetTempPath()
			$Assembly = [System.Reflection.Assembly]::Load($DllBytes)
			Import-Module -Assembly $Assembly
			$null = New-Item -Force -Path "$tmp\ActiveDirectory.psd1" -Value ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ActiveDirectory_psd1)))
			$null = New-Item -Force -Path "$tmp\ActiveDirectory.Types.ps1xml" -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ActiveDirectory_Types_ps1xml)))
			$null = New-Item -Force -Path "$tmp\ActiveDirectory.Format.ps1xml" -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ActiveDirectory_Format_ps1xml)))
			Import-Module $tmp\ActiveDirectory.psd1 -ErrorAction SilentlyContinue
			Remove-Item "$tmp\ActiveDirectory.psd1" -Force
			Remove-Item "$tmp\ActiveDirectory.Types.ps1xml" -Force
			Remove-Item "$tmp\ActiveDirectory.Format.ps1xml" -Force
		}
		"[*] Imported AD Module"
    }
}
Import-ActiveDirectory