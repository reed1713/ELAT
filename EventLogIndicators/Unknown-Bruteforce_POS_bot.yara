rule bruteforcing_bot
{ 
	meta:
		maltype = "botnet"
		reference = "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop"
		date = "3/11/2014"
		description = "botnet bruteforcing POS terms via RDP"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="\\AppData\\Roaming\\lsacs.exe"

	condition:
		all of them
}
