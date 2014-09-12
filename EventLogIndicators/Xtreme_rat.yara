rule xtreme_rat
{ 
	meta:
		maltype = "Xtreme RAT"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}
