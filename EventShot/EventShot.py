import win32evtlog
import os
import difflib
import ctypes
import time
import re

#################################################################
# Title: EventShot.py                                           #
# Author: Ryan Reed                                             #
# Last update: 04/09/2014                                       #
# Description: diffs the Window(s) event logs and outputs a     #
#              rough yara signature and a parsed event log file #
#################################################################                                                   

#sets the globals and initializes console colors
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12

FOREGROUND_BLUE = 0x01 # text color contains blue.
FOREGROUND_GREEN= 0x02 # text color contains green.
FOREGROUND_RED  = 0x04 # text color contains red.
FOREGROUND_INTENSITY = 0x08 # text color is intensified.

std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

# reads and parses the specified event log. yields a generator
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
                if count <= 500:
                    if interestingEvent(event,whitelist):
                        time = "date_time=\"" + str(event.TimeGenerated) + "\""
                        cat = "type=\"" + str(event.SourceName) + "\""
                        eventID = "eventid=\"" + str(event.EventID & 0x1FFFFFFF) + "\""
                        strings = "data=\"" + str(event.StringInserts).replace("\\\\","\\").replace("u'","'").replace("%%","") + "\""
                        result = []
                        result.append((time, cat, eventID, strings))
                        yield result
                
                else:
                    break

#takes the event data generated from ParseEvents and whitelist.txt list as agruments, searches through event data for matches
def interestingEvent(event,whitelist):

    interesting = True
    for item in whitelist:
        if re.search(item, str(event.StringInserts).replace("\\\\","\\").replace("u'","'").replace("%%",""), re.IGNORECASE):
            interesting = False
    return interesting

#gets choice and returns
def GetArg():
    
    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
    
    print " __________________"
    print "|                  |"
    print "| EVENT LOG    : # |"
    print "|__________________|"
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
        choice = int(raw_input("choose # and press enter to take 1st shot: "))
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
        else:
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
            print "[-] nope"
            print ""
            print "[-] try again"
            main()
    except ValueError:
            print ""
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
            print "[-] nope"
            print ""
            print "[-] try again"
            main()

#gets the console color
def SetColor(color, handle=std_out_handle):

    bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
    return bool

#puts together the yara rule template
def YaraFormat(input, output):

    output.write("rule <rule name>" + "\n")
    output.write("{ \n")
    output.write("\t" + "meta:" + "\n")
    output.write("\t\t" + "maltype = \"<enter maltype>\"" + "\n")
    output.write("\t\t" + "reference = \"<enter reference>\"" + "\n")
    output.write("\t\t" + "date = \"<enter date>\"" + "\n")
    output.write("\t\t" + "description = \"<enter description>\"" + "\n")
    output.write("\t" + "strings:" + "\n")
    for line in input:
        if not line.strip().startswith("date_time="):
            output.write("\t\t" + "$" + line)
    output.write("\t" + "condition:" + "\n")
    output.write("\t\t" + "all of them" + "\n")
    output.write("}" + "\n")

    input.close()
    output.close()

#diffs and parses the first and second shot. outputs rough yara sig and diff result to RESULTS dir
def main():
    
    try:
        os.remove("firstshot.txt") 
    except:
        pass
    try:
        os.remove("secondshot.txt")
    except:
        pass

    eventarg = GetArg()

    for eventargs in eventarg:
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        results = ParseEvents(eventargs)
        print "[+] writing: " + eventargs + "\n"
        if results:
            for result in results:
                linelist1 = result[0][0] + "\n" + result[0][1] + "\n" + result[0][2] + "\n" + result[0][3].replace("\\", "\\\\") + "\n"
                logfile1 = open("firstshot.txt", "a+")
                logfile1.write(linelist1)
                logfile1.close()
  
    raw_input("press enter to take 2nd shot...")
    print ""

    for eventargs in eventarg:
        print "[+] writing: " + eventargs + "\n"
        results2 = ParseEvents(eventargs)
        if results2:
            for result in results2:
                linelist2 = result[0][0] + "\n" + result[0][1] + "\n" + result[0][2] + "\n" + result[0][3].replace("\\", "\\\\") + "\n"
                logfile2 = open("secondshot.txt", "a+")
                logfile2.write(linelist2)
                logfile2.close()

#have to close and reopen file handles or else diff doesnt work
    file1 = open("firstshot.txt", 'r')
    file2 = open("secondshot.txt", 'r')
    diff = difflib.ndiff(file1.readlines(), file2.readlines())
    delta = ''.join(x[2:] for x in diff if x.startswith('+ '))
    file1.close()
    file2.close()

    if delta:
        filename = "..\\RESULTS\\EventShot_Results.txt"
        file = open(filename, "a+")
        file.write(delta)
        file.close()

        input = open("..\\RESULTS\\EventShot_Results.txt", "r+")
        output = open("..\\RESULTS\\EDIT_ME.yara", "w+")
        input.readline()
        YaraFormat(input, output)
           
        os.remove("firstshot.txt")
        os.remove("secondshot.txt") 
                          
        print "[+] done!"
        print ""
        print "results file and rough yara sig in the RESULTS directory" + "\n"
        time.sleep(3)
        os._exit(0)
    else:
        os.remove("firstshot.txt")
        os.remove("secondshot.txt")
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print "[-] no difference" + "\n"
        time.sleep(3)
        os._exit(0)

if __name__ == "__main__":
       
    SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY)

    print " _________________________________________________________"
    print "|  _______     _______ _   _ _____ ____  _   _  ___ _____ |"
    print "| | ____\ \   / / ____| \ | |_   _/ ___|| | | |/ _ \_   _||"
    print "| |  _|  \ \ / /|  _| |  \| | | | \___ \| |_| | | | || |  |"
    print "| | |___  \ V / | |___| |\  | | |  ___) |  _  | |_| || |  |"
    print "| |_____|  \_/  |_____|_| \_| |_| |____/|_| |_|\___/ |_|  |"
    print "|_________________________________________________________|"     

    if ctypes.windll.shell32.IsUserAnAdmin():
        try:
            whitelist = [process.strip() for process in open("whitelist.txt", "r")]
        except:
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
            print ""
            print "[-] whitelist.txt not found in EventShot root directory" + "\n"
            time.sleep(3)
            os._exit(0)
        finally:
            main()
    else:
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print ""
        print "[-] needs to be run as admin" + "\n"
        time.sleep(3)
        os._exit(0)

