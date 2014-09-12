rule Korplug
{ 
	meta:
		maltype = "Korplug Backdoor"
		reference = "http://www.symantec.com/connect/blogs/new-sample-backdoorkorplug-signed-stolen-certificate"
		description = "IOC looks for events associated with the KORPLUG Backdoor linked to the recent operation greedy wonk activity."
		
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\RasTls.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\rundll32.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\svchost.exe"
	condition:
		all of them
}
