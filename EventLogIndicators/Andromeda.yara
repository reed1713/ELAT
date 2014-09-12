rule andromeda
{ 
	meta:
		maltype = "Andromeda bot"
		description = "IOC looks for the creation or termination of a process associated with the Andromeda Trojan. The malware will execute the msiexec.exe within the suspicious directory. Shortly after, it creates and injects itself into the wuauctl.exe (windows update) process. It then attempts to beacon to its C2."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="AppData\\Local\\Temp\\_.net_\\msiexec.exe"

	condition:
		all of them
}
