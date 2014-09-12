ELAT (Event Log Analysis Toolkit)

SUMMARY
I ripped off the idea for EventShot from the tool regshot (takes snapshots of the registry), and applied that same thought to the event logs. The EventShot script simply takes a snapshot of the event log(s) you select, then takes a second snapshot after you're done with your analysis, diffs the two files and parses the output. EventScan, can either scan the live system event logs against the EventLogIndicators directory of yara sigs or you can place event log files in the SCAN dir and search it with your yara sigs. Both the tools and the yara sigs together create a way for the analyst to fully scope and detect malware via the windows event logs.

RUNNING
recommend using the windows executable code versions of EventScan and EventShot, which are found in both the EventScan dir and the EventShot dir. Both need to be run as admin.

FEATURES
EventShot
 	- root directory contains a file called whitelist.txt. Already has a few processes that I added from performing my own malware analysis. You can add noisy processes to this file using python regex (i.e. Windows\\system32\\svchost.exe or you could just specify svchost.exe). It then searches the data= line, and if it matches, it will remove the entire associated event, cleaning the output.
	- can choose from the Security, Application, System, or All event logs.
	- generates an rough yara signature and text file overview of the diff.

EventScan
 	- perform a live scan of either the Security, Application, System, or All event logs.
	- scan multiple event logs placed in the SCAN directory.
	- performs pattern matching using Yara.
	- outputs a text file with a report of the findings.

PROCEDURE

1) run Eventshot on malware analysis system

2) run malware

3) get indicators and edit yara output file accordingly

4) put finished .yara file in EventLogIndicators dir

5) perform live analysis or place event logs in SCAN dir to scan against newly created indicators

TIP
If you do plan on performing malware analysis using this tool, you should at least turn on process tracking within your windows malware vm via the windows security policy (run secpol.msc --> local policies --> audit policy --> audit process tracking --> click success and failure --> apply).

CAVEATS
	- EventShot has been tested and only works on 32bit vista and later windows systems.
	- EventScan has been tested and works on 32bit and 64bit windows vista and later systems. the SCAN dir feature may work on non windows systems (need to import yara), hasnt been tested.
	- output will be appended to the files in the RESULTS directory, unless you delete or remove the file(s) from the RESULTS dir before executing the code again
	- when you select the ALL option, results are appended to the file, which means so are the times. So if you have hits for the Security, Application, and System event logs, you will see the time sorted for each event log in the output file.
	- The current yara sigs are written for vista and later event log ids.
