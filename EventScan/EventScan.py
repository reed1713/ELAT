import os
import sys
import difflib
import ctypes
import time
import re
try:
    import win32evtlog #if run on a windows box
except:
    print ""
    print "[-] failed to import win32evtlog. options 1-4 wont work"
    pass
try:
	import yara
except:
    print ""
    print "[-] failed to import yara"
    time.sleep(3)
    os._exit(0)

########################################################################
# Title: EventScan.py                                                  #
# Author: Ryan Reed                                                    #
# Last update: 04/09/2014                                              #
# Description: Scans specified Windows event log(s) or scan directory  #
#              against yara sigs for signs of malicious activity       #
########################################################################

#sets the globals and initializes console colors
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12

FOREGROUND_BLUE = 0x01 # text color contains blue.
FOREGROUND_GREEN= 0x02 # text color contains green.
FOREGROUND_RED  = 0x04 # text color contains red.
FOREGROUND_INTENSITY = 0x08 # text color is intensified.

std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

#reads and parses the specified event log. yields a generator
def ParseEvents(eventtype, limit=None, server=None):

    server = None
    hand = win32evtlog.OpenEventLog(server,eventtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    events = 1
    count = 0

    while events:
        events = win32evtlog.ReadEventLog(hand, flags,0)
        if events:
            for event in events:
                count += 1
                time = "date_time=" + str(event.TimeGenerated)
                cat = "type=" + str(event.SourceName)
                eventID = "eventid=" + str(event.EventID & 0x1FFFFFFF)
                strings = "data=" + str(event.StringInserts).replace("\\\\","\\").replace("u'","'").replace("%%","")
                result = []
                result.append((time, cat, eventID, strings))
            yield result
        else:
            break

#gets the console argument
def GetArg():

    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)

    print " __________________    _____________________________"
    print "|                  |  |                             |"
    print "| EVENT LOG    : # |  | SEARCH \"SCAN\" DIRECTORY : 5 |"
    print "|__________________|  |_____________________________|"
    print "|                  |"
    print "| SECURITY     : 1 |"
    print "|                  |"
    print "| APPLICATION  : 2 |"
    print "|                  |"
    print "| SYSTEM       : 3 |"
    print "|                  |"
    print "| ALL          : 4 |"
    print "|__________________|"
    print ""

    try:
        choice = int(raw_input("choose # and press enter to start scan: "))
        print ""
        if choice == 1:
            eventT = ["Security"]
            return eventT
        elif choice == 2:
            eventT = ["Application"]
            return eventT
        elif choice == 3:
            eventT = ["System"]
            return eventT
        elif choice == 4:
            eventT = ["Security", "Application", "System"]
            return eventT
        elif choice == 5:
            eventT = 5
            return eventT
        else:
            SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
            print "[-] nope"
            print ""
            print "[-] try again"
            main()
    except ValueError:
            print ""
            SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
            print "[-] nope"
            print ""
            print "[-] try again"
            main()

#gets the console color
def SetColor(color, handle=std_out_handle):

    bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
    return bool

#scans the file against yara rules
def Scanner(scanfile, yaraRules):

    matches = []
    if len(str(scanfile)) > 0:
        for match in yaraRules.match(str(scanfile)):
            matches.append(str(match.rule) + "  |  meta: " + str(match.meta))
    try:
        return matches
    except:
        pass

#template for scan report
def WriteReport(report, fileName, results, rules):

    with open(report, "a+") as file:
        file.write("----------\n")
        file.write("Scanned: %s"%fileName + "\n\n")
        file.write("Rule: %s"%rules + "\n\n")
        if results:
            file.write("Hit: %s"%results[0] + "\n")
        else:
            file.write("No Hits" + "\n")
        file.write("----------\n")

#scans either the host event logs or files in the SCAN dir and matches against yara rules in the EventLogIndicators dir.
#outputs a report for both options, and for options 1-4, outputs the chosen event log(s) to a txt file.
def main():

    report = "..\\RESULTS\\EventScan_Report.txt"
    Rulesdir = "..\\EventLogIndicators"
    eventargs = GetArg()

    if eventargs == 5:
        scandir = ("..\\SCAN")
        if not os.listdir(scandir) == []:
            for files in os.listdir(scandir):
                if not os.listdir(Rulesdir) == []:
                    for rules in os.listdir(Rulesdir):
                        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                        rule = yara.compile(Rulesdir+"\\%s"%rules, error_on_warning=True)
                        results = Scanner(os.path.join(scandir, files), rule)
                        print "[+] scanning: " + str(files) + " file  |  rule: " + rules + "\n"
                        WriteReport(report, files, results, rules)
                        if results:
                            print "[+] found hit \n"
                        else:
                            SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
                            print "[-] no hits" + "\n"
                else:
                    SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
                    print "[-] no yara rules found in the EventLogIndicators directory"
                    time.sleep(3)
                    os._exit(0)
        else:
            SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
            print "[-] no files found in the SCAN directory"
            time.sleep(3)
            os._exit(0)

        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        raw_input("scan report in the RESULTS directory \n")

    else:
        for eventarg in eventargs:
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
            results = ParseEvents(eventarg)
            if not os.listdir(Rulesdir) == []:
                print "[+] writing: " + eventarg + " event log" + "\n"
                if results:
                    for result in results:
                        linelist1 = result[0][0] + "\n" + result[0][1] + "\n" + result[0][2] + "\n" + result[0][3] + "\n"
                        writefile = open("..\\RESULTS\\EventLog.txt", "a+")
                        writefile.write(linelist1)
                        writefile.close() #have to close the file before yara scan, or get permission errors
                file = open("..\\RESULTS\\EventLog.txt", "rb")

                for rules in os.listdir(Rulesdir):
                    files = eventarg
                    rule = yara.compile(Rulesdir+"\\%s"%rules, error_on_warning=True)
                    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                    print "[+] scanning: " + str(files) + " Event Log  |  rule: " + rules + "\n"
                    results = Scanner("..\\RESULTS\\EventLog.txt", rule)
                    WriteReport(report, files, results, rules)
                    if results:
                        print "[+] found hit \n"
                    else:
                        SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
                        print "[-] no hits" + "\n"
            else:
                SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
                print "[-] no yara rules found in the EventLogIndicators directory"
                time.sleep(3)
                os._exit(0)

        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        raw_input("scan report and event log text file in the RESULTS directory \n")

if __name__ == "__main__":

    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
    print " _____________________________________________________________"
    print "|  _______     _______ _   _ _____ ____   ____    _    _   _  |"
    print "| | ____\ \   / / ____| \ | |_   _/ ___| / ___|  / \  | \ | | |"
    print "| |  _|  \ \ / /|  _| |  \| | | | \___ \| |     / _ \ |  \| | |"
    print "| | |___  \ V / | |___| |\  | | |  ___) | |___ / ___ \| |\  | |"
    print "| |_____|  \_/  |_____|_| \_| |_| |____/ \____/_/   \_\_| \_| |"
    print "|_____________________________________________________________|"

    if ctypes.windll.shell32.IsUserAnAdmin():
            main()
    else:
        SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
        print ""
        print "[-] needs to be run as admin" + "\n"
        time.sleep(3)
        os._exit(0)
