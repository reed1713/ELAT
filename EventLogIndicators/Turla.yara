rule turla
{ 
	meta:
		maltype = "turla dropper"
		reference = "http://info.baesystemsdetica.com/rs/baesystems/images/snake_whitepaper.pdf"
		date = "3/13/2014"
		description = "This sample was pulled from the bae systems snake campaign report. The Turla dropper creates a file in teh temp dir and registers an auto start service call \"RPC Endpoint Locator\"."
	strings:

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="AppData\\Local\\Temp\\rsys.exe"

		$type1="Service Control Manager"
		$eventid1="7036"
		$data1="RPC Endpoint Locator"
		$data2="running"

		$type2="Service Control Manager"
		$eventid2="7045"
		$data3="RPC Endpoint Locator"
		$data4="user mode service" 
		$data5="auto start"

	condition:
    ($type and $eventid and $data) or ($type1 and $eventid1 and $data1 and $data2 and $type2 and $eventid2 and $data3 and $data4 and $data5)
}