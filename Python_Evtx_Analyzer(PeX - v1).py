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

from ast import Str
from cgi import print_arguments
import imp
from itertools import count
import datetime
import os
import os.path

import mmap  # Python's memory-mapped file input and output (I/O) library.

import argparse
from opcode import opname
from turtle import st  # argparse library is a parser for extra command-line options, arguments and sub-commands. This will
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


        # The lines of code up to variable countTextValues4 are responsible for reading the rule-based policy's filters in 
        # .txt form, that is included in ruleBasedPolicy folder. The filters are enumerated, the lines are splitted and after 
        # the file reading is closed the manipulated filtering info is stored into list_of_lists variable and printed on cmd 
        # terminal's screen. 

        # *.txt file opening.
        a_file = open("ruleBasedPolicy\RBPolicy.txt", "r")

        # *.txt file's reading of lines and storing them in the list_of_lists variable.
        lines = a_file.read()
        list_of_lists = lines.splitlines()
        
        # The open() .txt file is closed. 
        a_file.close()

        # The contents of the list_of_lists variable are printed on terminal.
        print(list_of_lists)

        # The eight global variables that follow are used in the textValueDom(int) function and the if..else conditional statements 
        # that deal with the manipulation, parsing and analyzing of the .evtx files.
        globvar = 0
        globvar1 = 0
        globvar2 = 0
        countTextValues = 0
        countTextValues1 = 0
        countTextValues2 = 0
        countTextValues3 = 0
        countTextValues4 = 0
        result1 = 0
        result2 = 0
        totatAnalyzedFiles1 = 0
        totatAnalyzedFiles2 = 0
        # result2 = str(result2)

        now = datetime.datetime.now()
        timestamp = str(now.strftime("%Y%m%d_%H%M%S"))
        os.chdir('suspiciousFilesIdentifiedReports')
        cwd = os.getcwd()
        name = 'threatAnalysisReport'
        data_folder = os.path.join(cwd)
        file_name = name + '_' + timestamp + '.txt' 
        # file = open("suspiciousFilesIdentifiedReports\\threatAnalysisReport.txt", "w")
        file = open(file_name, "w")
        file.write("Python_Evtx_Analyzer (PeX - v1) - EDR Threat Analysis Report of: \n")
        file.write(now.strftime("%Y-%m-%d %H:%M:%S")+"\n\n")
        file.write("The below files were identified as potentially suspicious for Lateral Movement behaviour.\n\n")
        file.close()

        # Function which handles minidom's xmlToDoc.getElementsByTagName() incorporated function.
        # The main utilities of this custom chunk of code, is to extract .evtx files element values 
        # included in the the specified through the int argument tag position, store it in node1 
        # variable, and afterwards extract the nodeValue included in node1.firstChild tag. Above that, 
        # the elements are counted based on their EventID int number into the myCount variable, which 
        # is upgraded by one every time a new element of the specified tag is found. 

        def textValueDom(int):
            # globvar variable stores element instances per tag and EventID.
            nonlocal globvar
            # countTextValues variable stores the total amount of the elements examined by this function, either
            # normal or suspicious.
            nonlocal countTextValues
            globvar = 0
            countTextValues = 0
            # Counter variable is used to count the number of elements found per tag.
            Counter = 0
            # myCount variable takes the values from Counter variable and implements them in a print() message function.
            myCount = int
            # dom_elements is used by minidom to store all the elements taged as 'Data'.
            dom_elements = xmlToDoc.getElementsByTagName("Data")
            # node1 imports only the specified per int argument element.
            node1 = dom_elements[int]
            # text_node1 takes the firstChild of node1. The firstChild property returns the first child node of the selected 
            # element. If the selected node has no children, this property returns NULL.
            text_node1 = node1.firstChild
            # text_value1 stores the value of the text_node1 variable and implements it in a print() function.
            text_value1 = text_node1.nodeValue
            print(text_value1)
            # countTextValues variable is updated per examined element.
            countTextValues +=1
            # The for loop iterated the list_of_lists with the filters implemented in the previous lines of code and compares it
            # per text_value1. If found Counter variable adds 1 and so as globvar does.

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
                    # file = open("suspiciousFilesIdentifiedReports\\threatAnalysisReport.txt", "a")
                    file = open(file_name, "a")
                    file.write(i+"\n\n")
                    file.close()
                
        def print_globvar():
            print(globvar)

        # Both variables store the necessary for the .evtx files analyzing process Sysmon EventIDs
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
                        # if eventsByID is included in eventIDValues1 = ['1', '2', '3', '4', '6', '7', '8', '9', '10', '11']
                        if eventsByID in eventIDValues1:
                            # The examined tags are printed in terminal's screen.
                            print(xmlToDoc.toprettyxml())
                            # textValueDom(int) examines the 10th elements aka 'CommandLine'
                            textValueDom(10)
                            print("The instances of ''Data Name = CommandLine'' element in the local tag are ", globvar)
                            # globvar1 stores the total number of ''Data Name = CommandLine'' elements.
                            globvar1 = globvar1 + globvar
                            print("In total, ", globvar1, "''Data Name = CommandLine'' elements were identified.")
                            # The total of all the examined elements is updated.
                            countTextValues1 = countTextValues1 + countTextValues
                            print("countTextValues1 ", countTextValues1)
                            # The examined tags are printed in terminal's screen.
                            # print(xmlToDoc.toprettyxml())
                            # textValueDom(int) examines the 4th elements aka 'Image'
                            textValueDom(4)
                            print("The instances of ''Data Name = Image'' element in the local tag are ", globvar)
                            # globvar2 stores the total number of ''Data Name = Image'' elements.
                            globvar2 = globvar2 + globvar
                            print("In total, ", globvar2, "''Data Name = Image'' elements were identified.")
                            # The total of all the examined elements is updated.
                            countTextValues2 = countTextValues2 + countTextValues
                            print("countTextValues2 ", countTextValues2)
                            # The total of the identified suspicious files that were identified are summed and printed.
                            print("ALERT, ALERT, ALERT...", globvar1 + globvar2, " incidents in total were identified as potentially prone to LM attacks.")
                            # The total of all the identified elements either normal or suspicious are summed and printed.
                            print((countTextValues1 + countTextValues2), "textValues were enumerated in total within this .evtx file.")
                            print("There is a ", ((100 * (globvar1 + globvar2)) / (countTextValues1 + countTextValues2)), "% percent possibility of being affected from a Lateral Movement Attack.") 
                            result1 = ((100 * (globvar1 + globvar2)) / (countTextValues1 + countTextValues2))
                            totatAnalyzedFiles1 = (countTextValues1 + countTextValues2)
                        # if eventsByID is included in eventIDValues2 = ['5']
                        elif eventsByID in eventIDValues2:
                            # The examined tags are printed in terminal's screen.
                            print(xmlToDoc.toprettyxml())
                            # textValueDom(int) examines the 4th elements aka 'Image'
                            textValueDom(4)
                            print("The instances of ''Data Name = Image'' element in the local tag are ", globvar)
                            # globvar2 stores the total number of ''Data Name = Image'' elements.
                            globvar2 = globvar2 + globvar
                            print("In total, ", globvar2, "''Data Name = Image'' elements were identified.")
                            # The total of all the examined elements is updated.
                            countTextValues3 = countTextValues3 + countTextValues
                            # The total of the identified suspicious files that were identified are summed and printed.
                            print("ALERT, ALERT, ALERT...", globvar2, " incidents in total were identified as potentially prone to LM attacks.")
                            # The total of all the identified elements either normal or suspicious are summed and printed.
                            print(countTextValues3, "textValues were enumerated in total within this .evtx file.")
                            print("There is a ", ((100 * (globvar2)) / (countTextValues3)), "% percent possibility of being affected from a Lateral Movement Attack.")
                            result2 = ((100 * (globvar2)) / (countTextValues3))
                            totatAnalyzedFiles2 = countTextValues3

        # //////////////////////////////////////////////////////////.evtx File Lateral Movement Analysis Final Report//////////////////////////////////////////////////////////
        
        # file = open("suspiciousFilesIdentifiedReports\\threatAnalysisReport.txt", "a")
        file = open(file_name, "a")
        file.write("Starting Time/Date:\n")
        file.write(now.strftime("%Y-%m-%d %H:%M:%S")+"\n\n")
        # file = open("suspiciousFilesIdentifiedReports\\threatAnalysisReport.txt", "a")
        file = open(file_name, "a")
        file.write("Ending Time/Date:\n")
        file.write(now.strftime("%Y-%m-%d %H:%M:%S")+"\n\n")
        if eventsByID in eventIDValues1: 
            file.write("There is a " + str(result1) + "% possibility of being under an attack involving Lateral Movement (with reference to Sysmon EventIDs 1-4, 6-22).\n")
            file.write("In total, " + str(globvar1) + " out of " + str(totatAnalyzedFiles1) + " ''Data Name = CommandLine'' elements were identified." + "\n")
            file.write("In total, " + str(globvar2) + " out of " + str(totatAnalyzedFiles1) + "''Data Name = Image'' elements were identified." + "\n")
        elif eventsByID in eventIDValues2:
            file.write("There is a " + str(result2) + "% percent possibility of being affected from a Lateral Movement Attack (with reference to Sysmon EventIDs 5).\n")
        file.close()   
                    
        evtxBuffer.close()  # mmap() evtxBuffer is closed.

        endingTag = "</EventIDs>"  # All the .xml files will end with the "/EventIDs" tag.

        # The "/EventIDs" tag will either been written to the output folder or to the standard output.
        if outputFolder:
            outputFolder.write(endingTag)
        else:
            print(endingTag)
        
    print("####################### The location of the analysis report is: #######################")
    print("#######################", data_folder, "#######################")

# The basic argument that makes our Python_Evtx_Analyzer() main executable.
if __name__ == '__main__':
    Python_Evtx_Analyzer()
