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

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="ProgramData\\RasTls\\rundll32.exe"

		$type2="Microsoft-Windows-Security-Auditing"
		$eventid2="4688"
		$data2="ProgramData\\RasTls\\svchost.exe"
	condition:
		all of them
}
