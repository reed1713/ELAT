rule Backdoor.Jolob
{
	meta:
		maltype = "Backdoor.Jolob"
		reference = "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks"
		description = "the backdoor registers an auto start service with the display name \"Network Access Management Agent\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."
	strings:   
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4673"
		$data = "Security"
		$data = "SeCreateGlobalPrivilege"
		$data = "Windows\\System32\\sysprep\\sysprep.exe" nocase
        
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4688"
		$data = "Windows\\System32\\sysprep\\sysprep.exe" nocase
        
		$type = "Service Control Manager"
		$eventid = "7036"
		$data = "Network Access Management Agent"
		$data = "running"
        
		$type = "Service Control Manager"
		$eventid = "7045"
		$data = "Network Access Management Agent"
		$data = "user mode service"
		$data = "auto start"      
    condition:
    	all of them
}