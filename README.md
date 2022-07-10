# Python_Evtx_Analyzer(PeX - v1)

The enclosed in this Github repository script, is a python analyzing scripting tool dubbed “Python_Evtx_Analyzer” (PeX - v1), which caters for the analysis of voluminous Sysmon logs, and therefore contributes to the identification of Lateral Movement events in a timely manner. With this portable and versatile chunk of code, the entries of Windows Event Logger and Sysmon .evtx files could be enumerated through dedicated filtering, to reveal the existence or not of possible Lateral Movement Attacks over Small Office Home Office (SOHO) Networks.

PeX’s events identification is based on Lateral Movement-oriented features that were extracted from Sysmon’s pre-configured rules in the enclosed config.xml file, as presented in the published pre-printed paper entitled "Revisiting the detection of Lateral Movement through Sysmon". What makes PeX special is its ability to be fully customizable by Incident Response researching teams to analyse and identify any kind of logging activity captured by Sysmon, either normal or malicious. As a result, PeX can be used in the context of other researchers in this timely field as it is made publicly available as open source in Github.
 

Along with PeX's (v1), the analyzer is initialized under the hood to identify the possibility of malicious Lateral Movement Attacks. All the associated filters are based on the Sysmon's EDR proposed policy in the aformentioned "Revisiting the detection of Lateral Movement through Sysmon" paper. The proposed EDR rule-based Sysmon's policy is also enclosed with PeX's repository as "config.xml" file. 

From an OS version’s perspective, the analyzer can run on all mainstream platforms, including Windows 10, MacOS Big Sur v11.6.5 and Ubuntu v22.04.

As a proof of concept, Pex was implemented with Python 3 on a VM Linux machine with 16 GB of RAM and a quad-core processor and evaluated over a 10-days dataset, regarding the analyzer’s detection and alerting rates. For reasons of reproducibility, but also for advancing research efforts in this area, the resulting dataset is publicly enclosed within the tool's repository. The .evtx dataset is aparted from four separate subsets, namely Normal, NormalVsMalicious01, NormalVsMalicious02 and FullSet, all enclosed in a .rar compressed file. 

The source code, along with PeX's supporting material of "config.xml" file, Evtx Datasets and Evtx Demo - Terminal Executions folders and the tools Readme file, are all available on https://github.com/ChristosSmiliotopoulos/Python_Evtx_Analyzer.git.

# Setup 

In order to re-build the source code contained in this repository there are two possible ways:

- Load it to the IDE of your choice (PyCharm is recommended, due to its undeniable characteristics that could not be
ommitted, including among the many benefits smart code completion, on-the-fly error inspection with highlighting and 
code refactoring). Import according to your IDE manual the referenced libraries in the main.py file, choose the relevant
to your system Python version (Python 3.9.1 was the version upon which the analyzer was created) and try the analyzer to the 
.evtx file of your choice.

- On the other hand, if no IDE is chose and the reproduction of the script is going to be done via terminal, cmd or 
PowerShell then keep in mind the steps that follow:
		
		- python setup.py install
		
		- pip install mmap
		
		- pip install argparse
				
		- pip install minidom-ext
		
		- pip install python-evtx
		
		- xml.etree.ElementTree is part of the python's standard library and no further installation is needed, since the 
		standard library is installed
		
		- To run the script via terminal / cmd / PowerShell execute the following command depending your OS and your .evtx file location:
		
			- Windows: python main.py -f "C:\Users\christossmiliotopoulos\Downloads\PtH_01.evtx" -i 5
			
			- macOS: python main.py -f "/Users/christossmiliotopoulos/Downloads/PtH_01.evtx" -i 5
			
			- Linux Distros: python main.py -f "/home/christossmiliotopoulos/Downloads/PtH_01.evtx" -i 5
			
		- Arguments -f and -i should be placed in the path and EventID values of your choice for the presented project to be productive 
		for you and your collegues. 

