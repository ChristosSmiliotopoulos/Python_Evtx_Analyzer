# This is .v1 of my newly created python parser, named python_Evtx_Parser(v1 - Beta) for .evtx files. With this
# portable and versatile chunk of code, the entries of Windows Event Logger and Sysmon .evtx files could be
# enumerated to reveal the existence or not of possible Lateral Movement Attacks over Small Office Home Office (SOHO)
# Networks. Along with .v1 of our python script, the parser is going to be initialized under the hood to identify the
# possibility of malicious Lateral Movement Attacks. All the associated filters are based on previous work done on
# the Sysmon config.xml file custom rules. What is special with this beta version of the python .evtx files parser is
# its independence from operating system platforms, namely Windows, macOS and any distribution of Linux OS. This
# would be analyzed thoroughly to the relevant README file which will accompany the distributed .py script on GitHub.

# The source code and supporting material of python_Evtx_Parser(v1 - Beta) is available on
# https://github.com/ChristosSmiliotopoulos/pythonParser.git private repository.

# ======================================================================================================================
# Importing necessary python libraries
# ======================================================================================================================

import mmap  # Python's memory-mapped file input and output (I/O) library.

import argparse  # argparse library is a parser for extra command-line options, arguments and sub-commands. This will
# make our python_Evtx_Parser(v1 - Beta) capable to be executed on any Windows cmd or powershell, macOS/Linux
# terminal environment.

from xml.dom import minidom  # Python's compact implementation of the DOM interface enables programmers to parse XML
# files via xml.dom.minidom xml parser.

from evtx.Evtx import FileHeader  # Python library for parsing Windows Event Log files (.evtx). Fileheader() function
# allows .evtx parsing based on the log file headers.

import evtx.Views  # Evtx library's sub-library which renders the given record into an XML document.

from xml.etree import ElementTree as xee  # ElementTree library allows a developer to parse and navigate an .xml,


# providing clever tree-based structure and giving him great insight to work with.

# ======================================================================================================================
# main() python function named python_Evtx_Parser(). This is the main block of code for the parser which only runs
# when called with PyCharm of any known console, terminal, cmd or powershell. All the necessary parameters will be
# passed to python_Evtx_Parser() as arguments.
# ======================================================================================================================

def python_Evtx_Parser():
    # argparse allows arguments to be passed together with the python_Evtx_Parser(v1 - Beta) execution either via
    # cmd, terminal, powershell or via PyCharm or any other python IDE.
    evtxParser = argparse.ArgumentParser(prog="python_Evtx_Parser", description="Enumeration of .evtx log files based "
                                                                                "on EventID with Lateral Movement "
                                                                                "Attacks oriented filtering.")
    # Input folder -f has been set in advance to "Run --> Edit Configurations" of PyCharm, but can also be set on the
    # fly during the parser's execution via command line.
    evtxParser.add_argument("-f", "--iFolder", dest="ifolder", type=str, required=True, help="System's location of the "
                                                                                             ".evtx input folder.")
    # -i argument allows the user to define the number of a specific id to be parsed.
    evtxParser.add_argument("-i", "--evtxId", dest="id", type=str, default="all",
                            help="The ID of the enumerated Events.")
    # If --outputFolder is set to True, then all the enumerated information will be saved to the folder path that
    # comes with the argument. If set to False, then the parsed content or strings will be forward to the standard
    # output (the terminal screen).
    evtxParser.add_argument("-o", "--outputFolder", dest="outputfolder", type=str, required=False, help="System's "
                                                                                                        "location for"
                                                                                                        " the output "
                                                                                                        "folder where "
                                                                                                        "the results "
                                                                                                        "are printed.")
    arguments = evtxParser.parse_args()  # The arguments are parsed to the specified variable.
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

        # Counter variable will be used to count the suspicious for Lateral Movement attacks network traffic.
        Counter = 0

        # ==============================================================================================================

        # The for function that follows iterates over each record. For that reason the evtx_file_xml_view() is called
        # from the Evtx.Views library. This function takes the fileheader object that was created with the
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
                        print(xmlToDoc.toprettyxml())

            # ==========================================================================================================
            # ==========================================================================================================
            # The statements that follow are responsible for filtering the parsed to xml .evtx files and print alert
            # messages for the identification of not of potential malicious Lateral Movement Attack network traffic.
            # For that purpose we use the ElementTree library instead of minidom xml.dom as it provides straightforward
            # filtering utility for the targeted image tags.
            # ==========================================================================================================
            # ==========================================================================================================

            # xmlToStr variable is passed as string to the doc variable.
            doc = xee.fromstring(xmlToStr)
            # The for loop() iterates over the tags of the xmlToStr .xml file, created with minidom, searching for the
            # requested tag images, as follows.
            for tag in doc.findall('Name'):
                if tag.attrib['Image'] == 'lsass' or tag.attrib['Image'] == 'klist' \
                        or tag.attrib['Image'] == 'conhost' or tag.attrib['Image'] == 'cmd' \
                        or tag.attrib['Image'] == 'PING' or tag.attrib['Image'] == '.exe' \
                        or tag.attrib['Image'] == 'dllhost' or tag.attrib['Image'] == 'svchost' \
                        or tag.attrib['Image'] == 'ipconfig' or tag.attrib['Image'] == 'mimikatz'\
                        or tag.attrib['Image'] == 'psexec' or tag.attrib['Image'] == 'psexesvc'\
                        or tag.attrib['Image'] == 'pskill' or tag.attrib['Image'] == 'wmiprvse'\
                        or tag.attrib['Image'] == 'sppsvc' or tag.attrib['Image'] == 'reg'\
                        or tag.attrib['Image'] == 'wininit' or tag.attrib['Image'] == 'whoami'\
                        or tag.attrib['Image'] == 'lazagne' or tag.attrib['CommandLine'] == 'sdelete'\
                        or tag.attrib['CommandLine'] == 'sekurlsa' or tag.attrib['CommandLine'] == 'reg SAVE'\
                        or tag.attrib['CommandLine'] == 'Invoke-DllInjection' or tag.attrib['CommandLine'] == 'Invoke-Shellcode'\
                        or tag.attrib['CommandLine'] == 'Invoke-WmiCommand' or tag.attrib['CommandLine'] == 'Get-Keystrokes'\
                        or tag.attrib['CommandLine'] == 'Get-TimedScreenshot' or tag.attrib['CommandLine'] == 'Get-VaultCredential'\
                        or tag.attrib['CommandLine'] == 'Invoke-CredentialInjection' or tag.attrib['CommandLine'] == 'mimikatz'\
                        or tag.attrib['CommandLine'] == 'Add-ScrnSaveBackdoor' or tag.attrib['CommandLine'] == 'Enabled-DuplicateToken'\
                        or tag.attrib['CommandLine'] == 'Invoke-PsUaCme' or tag.attrib['CommandLine'] == 'Remove-Update'\
                        or tag.attrib['CommandLine'] == 'Check-VM' or tag.attrib['CommandLine'] == 'Get-SiteListPassword'\
                        or tag.attrib['CommandLine'] == 'Get-System' or tag.attrib['CommandLine'] == 'BypassUAC'\
                        or tag.attrib['CommandLine'] == 'Invoke-Tater' or tag.attrib['CommandLine'] == 'PowerUp'\
                        or tag.attrib['CommandLine'] == 'Get-LSASecret' or tag.attrib['CommandLine'] == 'psscan'\
                        or tag.attrib['CommandLine'] == 'Invoke-PowerShellWMI' or tag.attrib['CommandLine'] == 'Add-Exfiltration'\
                        or tag.attrib['CommandLine'] == 'Add-Persistence' or tag.attrib['CommandLine'] == 'wmic shadowcopy delete'\
                        or tag.attrib['CommandLine'] == 'wbadmin delete catalog' or tag.attrib['CommandLine'] == 'set {default} recoveryenabled no'\
                        or tag.attrib['CommandLine'] == 'telnet' or tag.attrib['CommandLine'] == '-dumpcr'\
                        or tag.attrib['CommandLine'] == 'putty' or tag.attrib['CommandLine'] == 'bash'\
                        or tag.attrib['CommandLine'] == 'pssh' or tag.attrib['CommandLine'] == 'Invoke-TokenManipulation'\
                        or tag.attrib['CommandLine'] == 'Out-Minidump' or tag.attrib['CommandLine'] == 'VolumeShadowCopyTools'\
                        or tag.attrib['CommandLine'] == 'Invoke-ReflectivePEInjection' or tag.attrib['CommandLine'] == 'Invoke-DowngradeAccount'\
                        or tag.attrib['CommandLine'] == 'Get-ServiceUnquoted' or tag.attrib['CommandLine'] == 'Get-VulnSchTask'\
                        or tag.attrib['CommandLine'] == 'Get-WebConfig' or tag.attrib['CommandLine'] == 'Get-ServiceFilePermission'\
                        or tag.attrib['CommandLine'] == 'Get-ServicePermission' or tag.attrib['CommandLine'] == 'Invoke-ServiceAbuse'\
                        or tag.attrib['CommandLine'] == 'Get-RegAutoLogon' or tag.attrib['CommandLine'] == 'Get-Unconstrained'\
                        or tag.attrib['CommandLine'] == 'Add-RegBackdoor' or tag.attrib['CommandLine'] == 'Get-PassHashes'\
                        or tag.attrib['CommandLine'] == 'Show-TargetScreen' or tag.attrib['CommandLine'] == 'Port-Scan'\
                        or tag.attrib['CommandLine'] == 'netscan' or tag.attrib['Image'] == 'dfsrs'\
                        or tag.attrib['Image'] == 'dns' or tag.attrib['Image'] == 'WebServices'\
                        or tag.attrib['Image'] == 'services' or tag.attrib['Image'] == 'Users'\
                        or tag.attrib['Image'] == 'ProgramData' or tag.attrib['Image'] == 'Temp'\
                        or tag.attrib['Image'] == 'Sysmon' or tag.attrib['Image'] == 'Sysmon64'\
                        or tag.attrib['Image'] == 'notepad' or tag.attrib['Image'] == 'sc':
                    doc.remove(tag)
            print(xee.tostring(doc))
            countVar = xmlToStr.count("lsass") + xmlToStr.count("klist") +\
                       + xmlToStr.count("conhost") + xmlToStr.count("cmd") \
                       + xmlToStr.count("PING") + xmlToStr.count(".exe") \
                       + xmlToStr.count("dllhost") + xmlToStr.count("svchost") \
                       + xmlToStr.count("ipconfig") + xmlToStr.count("mimikatz") \
                       + xmlToStr.count("psexec") + xmlToStr.count("psexesvc") \
                       + xmlToStr.count("pskill") + xmlToStr.count("wmiprvse") \
                       + xmlToStr.count("sppsvc") + xmlToStr.count("reg")\
                       + xmlToStr.count("wininit") + xmlToStr.count("whoami")\
                       + xmlToStr.count("lazagne") + xmlToStr.count("sdelete")\
                       + xmlToStr.count("sekurlsa") + xmlToStr.count("reg SAVE")\
                       + xmlToStr.count("Invoke-DllInjection") + xmlToStr.count("Invoke-Shellcode")\
                       + xmlToStr.count("Invoke-WmiCommand") + xmlToStr.count("Get-Keystrokes")\
                       + xmlToStr.count("Get-TimedScreenshot") + xmlToStr.count("Get-VaultCredential")\
                       + xmlToStr.count("Invoke-CredentialInjection") + xmlToStr.count("mimikatz")\
                       + xmlToStr.count("Add-ScrnSaveBackdoor") + xmlToStr.count("Enabled-DuplicateToken")\
                       + xmlToStr.count("Invoke-PsUaCme") + xmlToStr.count("Remove-Update")\
                       + xmlToStr.count("Check-VM") + xmlToStr.count("Get-SiteListPassword")\
                       + xmlToStr.count("Get-System") + xmlToStr.count("BypassUAC")\
                       + xmlToStr.count("Invoke-Tater") + xmlToStr.count("PowerUp")\
                       + xmlToStr.count("Get-LSASecret") + xmlToStr.count("psscan")\
                       + xmlToStr.count("Invoke-PowerShellWMI") + xmlToStr.count("Add-Exfiltration")\
                       + xmlToStr.count("Add-Persistence") + xmlToStr.count("wmic shadowcopy delete")\
                       + xmlToStr.count("wbadmin delete catalog") + xmlToStr.count("set {default} recoveryenabled no")\
                       + xmlToStr.count("telnet") + xmlToStr.count("-dumpcr")\
                       + xmlToStr.count("putty") + xmlToStr.count("bash")\
                       + xmlToStr.count("pssh") + xmlToStr.count("Invoke-TokenManipulation")\
                       + xmlToStr.count("Out-Minidump") + xmlToStr.count("VolumeShadowCopyTools")\
                       + xmlToStr.count("Invoke-ReflectivePEInjection") + xmlToStr.count("Invoke-DowngradeAccount")\
                       + xmlToStr.count("Get-ServiceUnquoted") + xmlToStr.count("Get-VulnSchTask")\
                       + xmlToStr.count("Get-WebConfig") + xmlToStr.count("Get-ServiceFilePermission")\
                       + xmlToStr.count("Get-ServicePermission") + xmlToStr.count("Invoke-ServiceAbuse")\
                       + xmlToStr.count("Get-RegAutoLogon") + xmlToStr.count("Get-Unconstrained")\
                       + xmlToStr.count("Add-RegBackdoor") + xmlToStr.count("Get-PassHashes")\
                       + xmlToStr.count("Show-TargetScreen") + xmlToStr.count("Port-Scan")\
                       + xmlToStr.count("netscan") + xmlToStr.count("dfsrs")\
                       + xmlToStr.count("dns") + xmlToStr.count("WebServices")\
                       + xmlToStr.count("services") + xmlToStr.count("Users")\
                       + xmlToStr.count("ProgramData") + xmlToStr.count("Temp")\
                       + xmlToStr.count("Sysmon") + xmlToStr.count("Sysmon64")\
                       + xmlToStr.count("notepad") + xmlToStr.count("sc")
            print(countVar)

            if countVar >= 1:
                Counter += 1
                print(Counter)
                print("ATTENTION!!!", " ", Counter, " ",
                      "Events have been identified on the targeted system as suspicious for Lateral Movement Attack!!!")
            elif countVar == 0:
                Counter = Counter
                print(Counter)
                print("ATTENTION!!!", "No suspicious events for Lateral Movement Attacks have been identified on the "
                                      "targeted system!!!")

        print("Final Report: Filtering for Lateral Movement Attacks was finished successfully with ", Counter,
              " potentially malicious Events identified.")
        print("########SOS SOS SOS Attention should be paid to the targeted system.########")
        print("ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, "
              "\n ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, "
              "\n ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT, ")

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


# The basic argument that makes our python_Evtx_Parser() main executable.
if __name__ == '__main__':
    python_Evtx_Parser()
