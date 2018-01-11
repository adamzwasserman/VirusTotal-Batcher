# VirusTotal-Batcher
Requires Python 3.6, if it is not installed, it is better to install it with homebrew than to install it from the python.org install.
1) install homebrew: open Terminal and type (or copy/paste) the line below
	/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
2) type (or copy/paste) "brew install python3"

Full - proper - instructions can be found here: http://docs.python-guide.org/en/latest/starting/install3/osx/

If Python 3.6 IS installed, there are two possible ways it was done. We need to know which one:
1) open a terminal and type: "brew list""
2) if you see "python3" in the list, type "brew install openssl" and you are done, do not go to step 3 and on.
3) if you do not see "python3" in the list, close Terminal and go to your Applications folder
4) Find the Python 3.6 Folder and open it. Double click on "Install Certificates.command"
5) if you see errors, Terminal and type (or copy/paste) the lines below
	cd Applications/Python\ 3.6 
	sudo ./Install\ Certificates.command
6) all done

Install the three python files (vtbatch.py, VTlookup.py, config.py) in any directory of your choosing.

Open Terminal and type (or copy/paste) the two commands below (both are MIT license):
sudo -H pip3 install arrow
sudo -H pip3 install riprova

To run the program:
1) Make sure there is a file named VTlookup.txt in the same directory where you put the three files
2) Open Terminal, cd to the directory 
3) type: python3 vtbatch.py