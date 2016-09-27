rule PlugX
{ 
	meta:
		maltype = "plugX"
		reference = "http://www.fireeye.com/blog/technical/targeted-attack/2014/02/operation-greedywonk-multiple-economic-and-foreign-policy-sites-compromised-serving-up-flash-zero-day-exploit.html"
		description = "Malware creates a randomized directory within the appdata roaming directory and launches the malware. Should see multiple events for create process rundll32.exe and iexplorer.exe as it repeatedly uses iexplorer to launch the rundll32 process."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data=/\\AppData\\Roaming\\[0-9]{9,12}\VMwareCplLauncher\.exe/

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="\\Windows\\System32\\rundll32.exe"

		$type2="Microsoft-Windows-Security-Auditing"
		$eventid2="4688"
		$data2="Program Files\\Internet Explorer\\iexplore.exe"
	condition:
		all of them
}