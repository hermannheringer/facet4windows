<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.1.2
Date: 2024-11-04
Source: https://github.com/hermannheringer/
#>



 # Defining WPF environment
Add-Type -AssemblyName presentationframework, presentationcore
$wpf = @{ }
$inputXML = Get-Content -Path ".\WPFGUI\MainWindow.xaml"
$inputXMLClean = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace 'x:Class=".*?"','' -replace 'd:DesignHeight="\d*?"','' -replace 'd:DesignWidth="\d*?"',''
[xml]$xaml = $inputXMLClean
$reader = New-Object System.Xml.XmlNodeReader $xaml
$tempform = [Windows.Markup.XamlReader]::Load($reader)
$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach-Object {$wpf.Add($_.Name, $tempform.FindName($_.Name))}
$wpf.Facet4Image.source = ".\README\logo.png"



 # Parse and resolve paths in past previous arguments
$PSCommandArgs = @()
$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		 # Resolve full path to the included file
		$include = Resolve-Path $args[++$i] -ErrorAction SilentlyContinue
		$PSCommandArgs += "-include `"$include`""
		 # Import the included file as a module
		Import-Module -Name $include -ErrorAction SilentlyContinue
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		 # Resolve full path to the preset file
		$preset = Resolve-Path $args[++$i] -ErrorAction SilentlyContinue
		$PSCommandArgs += "-preset `"$preset`""
	}
	$i++
}



 # This code runs when the button is clicked
$wpf.runButton.add_Click({

    RequireAdmin | Invoke-Expression
	

	})

$wpf.cancelButton.add_Click({

	Exit

	})

$wpf.facet4Github.add_MouseLeftButtonDown({

	Start-process https://github.com/hermannheringer/facet4windows

	})


$wpf.facet4Window.ShowDialog() | Out-Null


