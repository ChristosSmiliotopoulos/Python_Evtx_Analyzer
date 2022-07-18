# This is a python analyzing scripting tool dubbed "Python_Evtx_Analyzer" (PeX - v1), which caters for the analysis of 
# voluminous Sysmon logs, and therefore contributes to the identification of Lateral Movement events in a timely manner. 
# With this portable and versatile chunk of code, the entries of Windows Event Logger and Sysmon .evtx files could be 
# enumerated through dedicated filtering, to reveal the existence or not of possible Lateral Movement Attacks over Small 
# Office Home Office (SOHO) Networks. PeX’s events identification is based on Lateral Movement-oriented features that 
# were extracted from Sysmon’s pre-configured rules in the enclosed config.xml file, as presented in the published 
# pre-printed paper entitled "Revisiting the detection of Lateral Movement through Sysmon". What makes PeX special is it's 
# ability to be fully customizable by Incident Response researching teams to analyse and identify any kind of logging '
# activity captured by Sysmon, either normal or malicious. As a result, PeX can be used in the context of other researchers 
# in this timely field as it is made publicly available as open source in Github.

# The source code, along with the following: 
# 	- PeX's supporting material, 
# 	- Sysmon's "config.xml" file, 
# 	- Evtx Datasets ("Normal", "NormalVsMalicious01", "NormalVsMalicious02", "Fullset") in one .rar file, 
# 	- Evtx Demo - Terminal Executions folders and 
# 	- PeX's Readme.md file, 
# can be downloaded from the tool's Github link, https://github.com/ChristosSmiliotopoulos/Python_Evtx_Analyzer.git.

# ======================================================================================================================
# Importing necessary python libraries
# ======================================================================================================================

from cgi import print_arguments
import imp
from itertools import count
import mmap  # Python's memory-mapped file input and output (I/O) library.

import argparse  # argparse library is a parser for extra command-line options, arguments and sub-commands. This will
# make "Python_Evtx_Analyzer (PeX - v1)" capable to incorporate argurment function capabilities on any Windows cmd or 
# powershell, macOS/Linux terminal environment.

from xml.dom import minidom  # Python's compact implementation of the DOM interface enables programmers to parse XML
# files via xml.dom.minidom xml parser.

from evtx.Evtx import FileHeader  # Python library for parsing Windows Event Log files (.evtx). Fileheader() function
# allows .evtx parsing based on the .evtx log file headers.

import evtx.Views  # Evtx library's sub-library which renders the given record into an XML document.

from xml.etree import ElementTree as xee

from pandas import value_counts  # ElementTree library allows a developer to parse, navigate and filter an .xml, 
# providing clever tree-based structure and giving him great insight to work with.

# ======================================================================================================================
# main() python function named Python_Evtx_Analyzer(). This is the main block of code for the analyzer which only runs
# when called with PyCharm of any known console, terminal, cmd or powershell. All the necessary parameters will be
# passed to Python_Evtx_Analyzer() as arguments.
# ======================================================================================================================

def Python_Evtx_Analyzer():
    # argparse allows arguments to be passed together with the "Python_Evtx_Analyzer (PeX - v1)" execution either via
    # cmd, terminal, powershell or via PyCharm or any other python IDE.
    evtxAnalyzer = argparse.ArgumentParser(prog="Python_Evtx_Analyzer", description="Enumeration of .evtx log files based "
                                                                                "on EventID with Lateral Movement "
                                                                                "Attacks oriented filtering.")
    # Input folder -f has been set in advance to "Run --> Edit Configurations" of PyCharm, but can also be set on the
    # fly during the analyzer's execution via command line.
    evtxAnalyzer.add_argument("-f", "--iFolder", dest="ifolder", type=str, required=True, help="System's location of the "
                                                                                             ".evtx input folder.")
    # -i argument allows the user to define the number of a specific id to be parsed and analyzed.
    evtxAnalyzer.add_argument("-i", "--evtxId", dest="id", type=str, default="all",
                            help="The ID of the enumerated Events.")
    # If --outputFolder is set to True, then all the enumerated information will be saved to the folder path that
    # comes with the argument. If set to False, then the parsed content or strings will be forward to the standard
    # output (the terminal screen).
    evtxAnalyzer.add_argument("-o", "--outputFolder", dest="outputfolder", type=str, required=False, help="System's "
                                                                                                        "location for"
                                                                                                        " the output "
                                                                                                        "folder where "
                                                                                                        "the results "
                                                                                                        "are printed.")
    arguments = evtxAnalyzer.parse_args()  # The arguments are parsed to the specified variable.
    outputFolder = False  # outputFolder is set to False.
    # If outputfolder is not None, it means that we have specified some outputs file.
    if arguments.outputfolder is not None:
        # outputfolder is opened with append ('a+') permission.
        outputFolder = open(arguments.outputfolder, 'a+')
    # The input folder (ifolder) is opened with read permission.
    with open(arguments.ifolder, 'r') as folder:
        # ifolder contents are mapped with mmap library. This step is very important because the evtxBuffer buffer
        # variable will be used as input to the FileHeader() function of the Evtx library that follows.
        evtxBuffer = mmap.mmap(folder.fileno(), 0, access=mmap.ACCESS_READ)
        # Offset is set to 0x00 in order to read the input file from the beginning.
        fileheader = FileHeader(evtxBuffer, 0x00)
        # The header of every xml file is stored to the xmlHeaderOutput variable.
        xmlHeaderOutput = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?><EventIDs>"
        if outputFolder:
            outputFolder.write(xmlHeaderOutput)
        else:
            print(xmlHeaderOutput)

        # The lines of code up to countTextValues4 is responsible for reading the rule-based policy's filters in .txt form, 
        # that is included in ruleBasedPolicy folder. The filters are enumerated, the lines are splitted and after the file
        # reading is closed all the manipulated filtering info is stored in list_of_lists variable and printed in termina's 
        # screen. 
        a_file = open("ruleBasedPolicy\RBPolicy.txt", "r")

        lines = a_file.read()
        list_of_lists = lines.splitlines()

        a_file.close()

        print(list_of_lists)

        globvar = 0
        globvar1 = 0
        globvar2 = 0
        countTextValues = 0
        countTextValues1 = 0
        countTextValues2 = 0
        countTextValues3 = 0
        countTextValues4 = 0

        def textValueDom(int):
            nonlocal globvar
            nonlocal countTextValues
            globvar = 0
            countTextValues = 0
            Counter = 0
            myCount = int
            dom_elements = xmlToDoc.getElementsByTagName("Data")
            node1 = dom_elements[int]
            text_node1 = node1.firstChild
            text_value1 = text_node1.nodeValue
            print(text_value1)
            countTextValues +=1
            for i in list_of_lists:
                # if text_value1 == i or text_value2 == i:
                if text_value1 == i:
                    print("Element found!!!")
                    Counter +=1
                    # print(Counter)
                    myCount = Counter
                    print(myCount, " Lateral Movement events have been found in total!!!")
                    globvar +=1
                    # print(globvar)

        def print_globvar():
            print(globvar)

        eventIDValues1 = ['1', '2', '3', '4', '6', '7', '8', '9', '10', '11']
        eventIDValues2 = ['5']


        # ==============================================================================================================

        # The for function that follows iterates over each record. For that reason the evtx_file_xml_view() is called
        # from the Evtx.Views library. This function takes the .xml fileheader object that was created with the
        # FileHeader() function of Evtx.Evtx library and creates a tuple of two different objects. xmlToStr object is
        # a string representation of a xml entry object and the second is a record object that for the purposes of our
        # project will not be used, but it is necessary for the function to run.
        for xmlToStr, record in evtx.Views.evtx_file_xml_view(fileheader):
            # The xmlToStr object is parsed to the variable after the newlines (\n) are eliminated.
            xmlToDoc = minidom.parseString(xmlToStr.replace("\n", ""))
            # The text inside the "EventID" tag is selected and stored to the eventsByID variable.
            eventsByID = xmlToDoc.getElementsByTagName("EventID")[0].childNodes[0].nodeValue
            # elseif() for xmlToDoc.toprettyxml() 'all' the EventIDs or specific arguments.id.
            if arguments.id == 'all':
                if outputFolder:
                    outputFolder.write(xmlToDoc.toprettyxml())
                else:
                    print(xmlToDoc.toprettyxml())
            else:
                if eventsByID == arguments.id:
                    if outputFolder:
                        outputFolder.write(xmlToDoc.toprettyxml())
                    else:
                        # if eventsByID == "1" or eventsByID == "2" or eventsByID == "3":
                        if eventsByID in eventIDValues1:
                            print(xmlToDoc.toprettyxml())
                            textValueDom(10)
                            print("The instances of globvar2 in the local tag are ", globvar)
                            globvar1 = globvar1 + globvar
                            print("globvar1 is ", globvar1)
                            countTextValues1 = countTextValues1 + countTextValues
                            print(xmlToDoc.toprettyxml())
                            textValueDom(4)
                            print("The instances of globvar2 in the local tag are ", globvar)
                            globvar2 = globvar2 + globvar
                            print("globvar2 is ", globvar2)
                            countTextValues2 = countTextValues2 + countTextValues
                            print("ALERT, ALERT, ALERT...", globvar1 + globvar2, " incidents were identified as potentially prone to LM attacks.")
                            print((countTextValues1 + countTextValues2), "textValues were enumerated in total within this .evtx file.")
                            print("There is a ", ((100 * (globvar1 + globvar2)) / (countTextValues1 + countTextValues2)), "% percent possibility of being affected from a Lateral Movement Attack.")
                        elif eventsByID in eventIDValues2:
                            print(xmlToDoc.toprettyxml())
                            textValueDom(4)
                            print("The instances of globvar2 in the local tag are ", globvar)
                            globvar2 = globvar2 + globvar
                            print("globvar2 is ", globvar2)
                            countTextValues3 = countTextValues3 + countTextValues
                            print("ALERT, ALERT, ALERT...", globvar2, " incidents were identified as potentially prone to LM attacks.")
                            print(countTextValues3, "textValues were enumerated in total within this .evtx file.")
                            print("There is a ", ((100 * (globvar2)) / (countTextValues3)), "% percent possibility of being affected from a Lateral Movement Attack.")

                        
                        # print(xmlToDoc.toprettyxml())
                        # dom_elements = xmlToDoc.getElementsByTagName("Data")
                        # node1 = dom_elements[4]
                        # text_node1 = node1.firstChild
                        # text_value1 = text_node1.nodeValue
                        # print(text_value1)

                        # node2 = dom_elements[10]
                        # text_node2 = node2.firstChild
                        # text_value2 = text_node2.nodeValue
                        # print(text_value2)

                        # for i in list_of_lists:
                        #     # if text_value1 == i or text_value2 == i:
                        #     if text_value1 == i:
                        #         print("Element found!!!")
                        #         Counter +=1
                        #         print(Counter)
                        #         myCount = Counter
                        # print(myCount, " Lateral Movement events have been found in total!!!")
                       
            # ==========================================================================================================
            # ==========================================================================================================
            # The statements that follow are responsible for filtering the parsed to xml .evtx files and print alert
            # messages for the identification of not of potential malicious Lateral Movement Attack network traffic.
            # For that purpose we use the ElementTree library instead of minidom xml.dom as it provides straightforward
            # filtering utility for the targeted image tags.
            # ==========================================================================================================
            # ==========================================================================================================

        #     # xmlToStr variable is passed as string to the doc variable.
        #     doc = xee.fromstring(xmlToStr)
        #     # The for loop() iterates over the tags of the xmlToStr .xml file, created with minidom, searching for the
        #     # requested tag images, as follows.
        #     for tag in doc.findall('Name'):
        #         if tag.attrib['Image'] == 'lsass' or tag.attrib['Image'] == 'klist' \
        #                 or tag.attrib['Image'] == 'conhost' or tag.attrib['Image'] == 'cmd' \
        #                 or tag.attrib['Image'] == 'PING' or tag.attrib['Image'] == '.exe' \
        #                 or tag.attrib['Image'] == 'dllhost' or tag.attrib['Image'] == 'svchost' \
        #                 or tag.attrib['Image'] == 'ipconfig' or tag.attrib['Image'] == 'mimikatz'\
        #                 or tag.attrib['Image'] == 'psexec' or tag.attrib['Image'] == 'psexesvc'\
        #                 or tag.attrib['Image'] == 'pskill' or tag.attrib['Image'] == 'wmiprvse'\
        #                 or tag.attrib['Image'] == 'sppsvc' or tag.attrib['Image'] == 'reg'\
        #                 or tag.attrib['Image'] == 'wininit' or tag.attrib['Image'] == 'whoami'\
        #                 or tag.attrib['Image'] == 'lazagne' or tag.attrib['CommandLine'] == 'sdelete'\
        #                 or tag.attrib['CommandLine'] == 'sekurlsa' or tag.attrib['CommandLine'] == 'reg SAVE'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-DllInjection' or tag.attrib['CommandLine'] == 'Invoke-Shellcode'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-WmiCommand' or tag.attrib['CommandLine'] == 'Get-Keystrokes'\
        #                 or tag.attrib['CommandLine'] == 'Get-TimedScreenshot' or tag.attrib['CommandLine'] == 'Get-VaultCredential'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-CredentialInjection' or tag.attrib['CommandLine'] == 'mimikatz'\
        #                 or tag.attrib['CommandLine'] == 'Add-ScrnSaveBackdoor' or tag.attrib['CommandLine'] == 'Enabled-DuplicateToken'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-PsUaCme' or tag.attrib['CommandLine'] == 'Remove-Update'\
        #                 or tag.attrib['CommandLine'] == 'Check-VM' or tag.attrib['CommandLine'] == 'Get-SiteListPassword'\
        #                 or tag.attrib['CommandLine'] == 'Get-System' or tag.attrib['CommandLine'] == 'BypassUAC'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-Tater' or tag.attrib['CommandLine'] == 'PowerUp'\
        #                 or tag.attrib['CommandLine'] == 'Get-LSASecret' or tag.attrib['CommandLine'] == 'psscan'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-PowerShellWMI' or tag.attrib['CommandLine'] == 'Add-Exfiltration'\
        #                 or tag.attrib['CommandLine'] == 'Add-Persistence' or tag.attrib['CommandLine'] == 'wmic shadowcopy delete'\
        #                 or tag.attrib['CommandLine'] == 'wbadmin delete catalog' or tag.attrib['CommandLine'] == 'set {default} recoveryenabled no'\
        #                 or tag.attrib['CommandLine'] == 'telnet' or tag.attrib['CommandLine'] == '-dumpcr'\
        #                 or tag.attrib['CommandLine'] == 'putty' or tag.attrib['CommandLine'] == 'bash'\
        #                 or tag.attrib['CommandLine'] == 'pssh' or tag.attrib['CommandLine'] == 'Invoke-TokenManipulation'\
        #                 or tag.attrib['CommandLine'] == 'Out-Minidump' or tag.attrib['CommandLine'] == 'VolumeShadowCopyTools'\
        #                 or tag.attrib['CommandLine'] == 'Invoke-ReflectivePEInjection' or tag.attrib['CommandLine'] == 'Invoke-DowngradeAccount'\
        #                 or tag.attrib['CommandLine'] == 'Get-ServiceUnquoted' or tag.attrib['CommandLine'] == 'Get-VulnSchTask'\
        #                 or tag.attrib['CommandLine'] == 'Get-WebConfig' or tag.attrib['CommandLine'] == 'Get-ServiceFilePermission'\
        #                 or tag.attrib['CommandLine'] == 'Get-ServicePermission' or tag.attrib['CommandLine'] == 'Invoke-ServiceAbuse'\
        #                 or tag.attrib['CommandLine'] == 'Get-RegAutoLogon' or tag.attrib['CommandLine'] == 'Get-Unconstrained'\
        #                 or tag.attrib['CommandLine'] == 'Add-RegBackdoor' or tag.attrib['CommandLine'] == 'Get-PassHashes'\
        #                 or tag.attrib['CommandLine'] == 'Show-TargetScreen' or tag.attrib['CommandLine'] == 'Port-Scan'\
        #                 or tag.attrib['CommandLine'] == 'netscan' or tag.attrib['Image'] == 'dfsrs'\
        #                 or tag.attrib['Image'] == 'dns' or tag.attrib['Image'] == 'WebServices'\
        #                 or tag.attrib['Image'] == 'services' or tag.attrib['Image'] == 'Users'\
        #                 or tag.attrib['Image'] == 'ProgramData' or tag.attrib['Image'] == 'Temp'\
        #                 or tag.attrib['Image'] == 'Sysmon' or tag.attrib['Image'] == 'Sysmon64'\
        #                 or tag.attrib['Image'] == 'notepad' or tag.attrib['Image'] == 'sc':
        #             doc.remove(tag)
        #     # print(xee.tostring(doc))
        #     countVar = xmlToStr.count("lsass") + xmlToStr.count("klist") +\
        #                + xmlToStr.count("conhost") + xmlToStr.count("cmd") \
        #                + xmlToStr.count("PING") + xmlToStr.count(".exe") \
        #                + xmlToStr.count("dllhost") + xmlToStr.count("svchost") \
        #                + xmlToStr.count("ipconfig") + xmlToStr.count("mimikatz") \
        #                + xmlToStr.count("psexec") + xmlToStr.count("psexesvc") \
        #                + xmlToStr.count("pskill") + xmlToStr.count("wmiprvse") \
        #                + xmlToStr.count("sppsvc") + xmlToStr.count("reg")\
        #                + xmlToStr.count("wininit") + xmlToStr.count("whoami")\
        #                + xmlToStr.count("lazagne") + xmlToStr.count("sdelete")\
        #                + xmlToStr.count("sekurlsa") + xmlToStr.count("reg SAVE")\
        #                + xmlToStr.count("Invoke-DllInjection") + xmlToStr.count("Invoke-Shellcode")\
        #                + xmlToStr.count("Invoke-WmiCommand") + xmlToStr.count("Get-Keystrokes")\
        #                + xmlToStr.count("Get-TimedScreenshot") + xmlToStr.count("Get-VaultCredential")\
        #                + xmlToStr.count("Invoke-CredentialInjection") + xmlToStr.count("mimikatz")\
        #                + xmlToStr.count("Add-ScrnSaveBackdoor") + xmlToStr.count("Enabled-DuplicateToken")\
        #                + xmlToStr.count("Invoke-PsUaCme") + xmlToStr.count("Remove-Update")\
        #                + xmlToStr.count("Check-VM") + xmlToStr.count("Get-SiteListPassword")\
        #                + xmlToStr.count("Get-System") + xmlToStr.count("BypassUAC")\
        #                + xmlToStr.count("Invoke-Tater") + xmlToStr.count("PowerUp")\
        #                + xmlToStr.count("Get-LSASecret") + xmlToStr.count("psscan")\
        #                + xmlToStr.count("Invoke-PowerShellWMI") + xmlToStr.count("Add-Exfiltration")\
        #                + xmlToStr.count("Add-Persistence") + xmlToStr.count("wmic shadowcopy delete")\
        #                + xmlToStr.count("wbadmin delete catalog") + xmlToStr.count("set {default} recoveryenabled no")\
        #                + xmlToStr.count("telnet") + xmlToStr.count("-dumpcr")\
        #                + xmlToStr.count("putty") + xmlToStr.count("bash")\
        #                + xmlToStr.count("pssh") + xmlToStr.count("Invoke-TokenManipulation")\
        #                + xmlToStr.count("Out-Minidump") + xmlToStr.count("VolumeShadowCopyTools")\
        #                + xmlToStr.count("Invoke-ReflectivePEInjection") + xmlToStr.count("Invoke-DowngradeAccount")\
        #                + xmlToStr.count("Get-ServiceUnquoted") + xmlToStr.count("Get-VulnSchTask")\
        #                + xmlToStr.count("Get-WebConfig") + xmlToStr.count("Get-ServiceFilePermission")\
        #                + xmlToStr.count("Get-ServicePermission") + xmlToStr.count("Invoke-ServiceAbuse")\
        #                + xmlToStr.count("Get-RegAutoLogon") + xmlToStr.count("Get-Unconstrained")\
        #                + xmlToStr.count("Add-RegBackdoor") + xmlToStr.count("Get-PassHashes")\
        #                + xmlToStr.count("Show-TargetScreen") + xmlToStr.count("Port-Scan")\
        #                + xmlToStr.count("netscan") + xmlToStr.count("dfsrs")\
        #                + xmlToStr.count("dns") + xmlToStr.count("WebServices")\
        #                + xmlToStr.count("services") + xmlToStr.count("Users")\
        #                + xmlToStr.count("ProgramData") + xmlToStr.count("Temp")\
        #                + xmlToStr.count("Sysmon") + xmlToStr.count("Sysmon64")\
        #                + xmlToStr.count("notepad") + xmlToStr.count("sc")
        #     print(countVar)

        #     if countVar >= 1:
        #         Counter += 1
        #         print(Counter)
        #         print("ATTENTION!!!", " ", Counter, " ",
        #               "Events have been identified on the targeted system as suspicious for Lateral Movement Attack!!!")
        #     elif countVar == 0:
        #         Counter = Counter
        #         print(Counter)
        #         print("ATTENTION!!!", "No suspicious events for Lateral Movement Attacks have been identified on the "
        #                               "targeted system!!!")

        # print("Final Report: Filtering for Lateral Movement Attacks was finished successfully with ", Counter,
        #       " potentially malicious Events identified.")
        # print("########SOS SOS SOS Attention should be paid to the targeted system.########")
        # print("ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, "
        #       "\n ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, "
        #       "\n ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ")

        # ==============================================================================================================
        # This is the END of the filtering process
        # ==============================================================================================================

        evtxBuffer.close()  # mmap() evtxBuffer is closed.

        endingTag = "</EventIDs>"  # All the .xml files will end with the "/EventIDs" tag.

        # The "/EventIDs" tag will either been written to the output folder or to the standard output.
        if outputFolder:
            outputFolder.write(endingTag)
        else:
            print(endingTag)


# The basic argument that makes our Python_Evtx_Analyzer() main executable.
if __name__ == '__main__':
    Python_Evtx_Analyzer()
