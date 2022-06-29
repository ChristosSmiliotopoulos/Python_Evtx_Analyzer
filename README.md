# python_Evtx_Analyzer-v1---Beta-

This is .v1 of my newly created python parser, named python_Evtx_Parser(v1 - Beta) for .evtx files. With this
portable and versatile chunk of code, the entries of Windows Event Logger and Sysmon .evtx files could be
enumerated to reveal the existence or not of possible Lateral Movement Attacks over Small Office Home Office (SOHO)
Networks. Along with .v1 of our python script, the parser is going to be initialized under the hood to identify the
possibility of malicious Lateral Movement Attacks. All the associated filters are based on previous work done on
the Sysmon config.xml file custom rules. What is special with this beta version of the python .evtx files parser is
its independence from operating system platforms, namely Windows, macOS and any distribution of Linux OS. This
would be analyzed thoroughly to the relevant README file which will accompany the distributed .py script on GitHub.

The source code and supporting material of python_Evtx_Parser(v1 - Beta) is available on
https://github.com/ChristosSmiliotopoulos/pythonParser.git private repository.

# Setup 

In order to re-build the source code contained in this repository there are two possible ways:

- Load it to the IDE of your choice (PyCharm is recommended, due to its undeniable characteristics that could not be
ommitted, including among the many benefits smart code completion, on-the-fly error inspection with highlighting and 
code refactoring). Import according to your IDE manual the referenced libraries in the main.py file, choose the relevant
to your system Python version (Python 3.9.1 was the version upon which the parser was created) and try the parser to the 
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

