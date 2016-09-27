import os
import sys
import difflib
import ctypes
import time
import re
import pywintypes
import mmap
import contextlib
try:
    from Evtx.Evtx import FileHeader, Evtx
    from Evtx.Views import evtx_file_xml_view
except:
    print
    print "[-] failed to import Evtx."
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

FOREGROUND_AQUA = 0x03 # text color contains AQUA.
FOREGROUND_GREEN= 0x02 # text color contains green.
FOREGROUND_RED  = 0x04 # text color contains red.
FOREGROUND_WHITE = 0x07
FOREGROUND_INTENSITY = 0x08 # text color is intensified.

std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

#reads and parses the specified event log. yields a generator
def ParseEvents(eventtype,server):

    try:
        hand = win32evtlog.OpenEventLog(server,eventtype)
    except pywintypes.error as e:
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print e[2]
        SetColor(FOREGROUND_WHITE)
        os._exit(0)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    events = 1
    count = 0
    result = []
    results = result.append
    while events:
        events = win32evtlog.ReadEventLog(hand, flags,0)
        if events:
            for event in events:
                count += 1
                time = "date_time= %s" % str(event.TimeGenerated)
                cat = "type= %s" % str(event.SourceName)
                eventID = "eventid= %s" % str(event.EventID & 0x1FFFFFFF)
                strings = "data= %s" % str(event.StringInserts).replace("\\\\","\\").replace("u'","'").replace("%%","")
                results((time, cat, eventID, strings))
                bar_len = 55
                filled_len = int(round(bar_len * count / float(total)))
                percents = round(100.0 * count / float(total), 1)
                bar = '=' * filled_len + '-' * (bar_len - filled_len)
                sys.stdout.write('[%s] %s%s %s/%s \r' % (bar, percents, '%', count, total))
                sys.stdout.flush()
            yield result
    
    if total == count:
        SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
        print
        print "Successfully read all", total, "records"
        print
    else:
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print
        print "Couldn't get all records - reported %d, but found %d" % (total, count)
        print "(Note that some other app may have written records while we were running!)"
        print
    win32evtlog.CloseEventLog(hand)

#converts evtx to readable format
#https://github.com/williballenthin/python-evtx/blob/master/scripts/evtxdump.py
def ParseEvtx(files):
    writefile = open("..\\RESULTS\\EventLog.txt", "a+")
    
    with Evtx(files) as evtx:
        total = sum(1 for i in evtx.records())
    
    with open(files, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            writefile.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>")
            writefile.write("<Events>")
            count = 0
            for xml, record in evtx_file_xml_view(fh):
                count += 1
                writefile.write(ascii(xml))
                bar_len = 55
                filled_len = int(round(bar_len * count / float(total)))
                percents = round(100.0 * count / float(total), 1)
                bar = '=' * filled_len + '-' * (bar_len - filled_len)
                sys.stdout.write('[%s] %s%s %s/%s \r' % (bar, percents, '%', count, total))
                sys.stdout.flush()
                writefile.write("</Events>")
    print
    print
    
def ascii(s):
    return s.encode('ascii', 'replace').decode('ascii')
            
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
            server = str(raw_input("enter asset name: "))
            eventT = ["Security"]
            return eventT, server
        elif choice == 2:
            server = str(raw_input("enter asset name: "))
            eventT = ["Application"]
            return eventT, server
        elif choice == 3:
            server = str(raw_input("enter asset name: "))
            eventT = ["System"]
            return eventT, server
        elif choice == 4:
            server = str(raw_input("enter asset name: "))
            eventT = ["Security", "Application", "System"]
            return eventT, server
        elif choice == 5:
            server = None
            eventT = 5
            return eventT, server
        else:
            SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
            print "[-] nope"
            print ""
            print "[-] try again"
            main()
    except ValueError:
            print ""
            SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
            print "[-] nope Value error"
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
    eventargs,server = GetArg()

    if eventargs == 5:
        scandir = ("..\\SCAN")
        if not os.listdir(scandir) == []:
            for files in os.listdir(scandir):
                if files.endswith('.evtx'):
                    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                    print "[+] writing: " + files + " in Scan Directory\n"
                    ParseEvtx(scandir+'\\'+files)
                
        else:
                SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
                print "[-] no files found in the SCAN directory"
                time.sleep(3)
                os._exit(0)
            
        if not os.listdir(Rulesdir) == []:
            for rules in os.listdir(Rulesdir):
                rule = yara.compile(Rulesdir+"\\%s"%rules, error_on_warning=False)
                SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                print "[+] scanning: Event Logs From Scan Directory  |  rule: " + rules + "\n"
                results = Scanner("..\\RESULTS\\EventLog.txt", rule)
                WriteReport(report, files, results, rules)
                if results:
                    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
                    print "[+] found hit \n"
                    SetColor(FOREGROUND_WHITE)
                else:
                    SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
                    print "[-] no hits" + "\n"
                    SetColor(FOREGROUND_WHITE)
        else:
            SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
            print "[-] no yara rules found in the EventLogIndicators directory"
            time.sleep(3)
            os._exit(0)

        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        raw_input("scan report in the RESULTS directory \n")
        SetColor(FOREGROUND_WHITE)

    else:
        for eventarg in eventargs:
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
            results = ParseEvents(eventarg,server)
            if not os.listdir(Rulesdir) == []:
                print "[+] writing: " + eventarg + " event log" + "\n"
                writefile = open("..\\RESULTS\\EventLog.txt", "a+")
                output = writefile.write
                if results:
                    for result in results:
                        linelist1 = "%s\n%s\n%s\n%s\n" % (result[0][0], result[0][1], result[0][2], result[0][3])
                        output(linelist1)
                writefile.close() #have to close the file before yara scan, or get permission errors
            else:
                SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
                print "[-] no yara rules found in the EventLogIndicators directory"
                SetColor(FOREGROUND_WHITE)
                time.sleep(3)
                os._exit(0)

        file = open("..\\RESULTS\\EventLog.txt", "rb")

        for rules in os.listdir(Rulesdir):
            files = ', '.join(eventargs)
            rule = yara.compile(Rulesdir+"\\%s"%rules, error_on_warning=False)
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
            print "[+] scanning: " + str(files) + " Event Log  |  rule: " + rules + "\n"
            results = Scanner("..\\RESULTS\\EventLog.txt", rule)
            WriteReport(report, files, results, rules)
            if results:
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
                print "[+] found hit \n"
                SetColor(FOREGROUND_WHITE)
            else:
                SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
                print "[-] no hits" + "\n"
                SetColor(FOREGROUND_WHITE)        
                
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        raw_input("scan report and event log text file in the RESULTS directory \n")
        SetColor(FOREGROUND_WHITE)

if __name__ == "__main__":
    
    ctypes.windll.kernel32.SetConsoleTitleA("EventScan")
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
        SetColor(FOREGROUND_AQUA | FOREGROUND_INTENSITY)
        print ""
        print "[-] needs to be run as admin" + "\n"
        SetColor(FOREGROUND_WHITE)
        time.sleep(3)
        os._exit(0)
