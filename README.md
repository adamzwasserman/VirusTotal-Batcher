
# VirusTotal-Batcher

VTB is a command line program for  anyone who uses VirusTotal primarily for lookups (of domain names, urls, and ips) and wants to do so in batches instead of one by one on the website.

Features:
 - the ability to force a rescan of a list of URLs, 
 - expansion of IP addresses written in CIDR ("slash") notation
 - a "sane" column layout 
 - expansion of VT results into multiple rows
 - a timestamped results file with results from successful queries
 - a timestamped failures files with a list of all the queries that failed 
 
 also
 
 - automatic backoff and retry if the VT Rate limiter kicks in 
 - a config file that allows you to set all of the below:
	 - your own API Key
	 - rate-limit friendly wait-time between queries (1.5 seconds recommended)
	 - maximum time in seconds to retire before failing the query


# Installation Instructions
*Special instructions for Macintosh users, see below*

VTB requires Python 3.6. It uses two MIT licensed 3rd party modules. The excellent `arrow` for better time handling than the built-in python modules, and the equally excellent `reprova` which implements backoff and retry as a decorator (easy-peasy).

1) Install the three python files (vtbatch.py, VTlookup.py, config.py) in the directory of your choosing.

2) Open Terminal and type (or copy/paste) the two commands below (both modules use the MIT license):<p>`pip3 install arrow`<p>`pip3 install riprova`
3) edit the config.py file and replace "pu_APIKEY_here" with your own APIKey

To run the program:
1) Make sure there is a file named `VTlookup.txt` in the same directory where you put the three files
2) Open a terminal, make sure your current directory is the one with the program 
3) Type: `python3 vtbatch.py`
4) Feel the power

**===Special instructions for Macintosh users===**

If you are on a Macintosh, be aware that the python.org installer will install its own version of openssl that will not access the system certificates which will cause openssl to reject the VirusTotal certificate, which in turn will cause the program to fail.

If Python 3.6 is not yet installed, it is better to install it with homebrew than to install it from the python.org installer.

1) install homebrew: open Terminal and type (or copy/paste) the line below (copy everything from "/urs" up to "/install"):
`/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install`
2) type (or copy/paste) `brew install python3`

Full - proper - instructions can be found here: http://docs.python-guide.org/en/latest/starting/install3/osx/

If Python 3.6 IS installed, there are two possible ways it was done. We need to know which one:
1) open a terminal and type: `brew list`
2) if you see "python3" in the list, type `brew install openssl` and you are done. Do not go to step 3 and on.
3) if you do not see "python3" in the list, close Terminal and go to your Applications folder
4) Find the Python 3.6 Folder and open it. Double click on "Install Certificates.command"
5) if you see errors, Terminal and type (or copy/paste) the lines below:
`cd Applications/Python\ 3.6`
`sudo ./Install\ Certificates.command`
6) all done
> Written with [StackEdit](https://stackedit.io/).
