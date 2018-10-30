#VirusTotal Batch Machine Gun
VirusTotal Machine Gun (VTMG) is a multi-threaded CLI program allowing *massive* queries of IPs, hosts & domains, and URLs at VirusTotal.

Designed by Spamfighter666, coded by Adam.

## Notable Features

######  - VTMG can eat individual IPs, or as **CIDR ranges** up to a /16. That's big.
######  -  If you'd like, VTMG can do ***A Record Resolutions*** so the historical record is juxtaposed with actual state of affairs. A contrast and compare kinda thing.
######  -  Moreover, VTMG is as **fast *AF***, (thus the Machine Gun bit of the name). How fast? Like I once saw it do 300,000 URLs in under an hour. That's fast. So fast that last night it turned off the light switch in the room and was in bed before the room was dark. That's fast.
######  -  A **Force Submit** function in VTMG bends VirusTotal to your iron will, and invokes a scan of URLs for scoring or re-scoring. PROTIP: If a domain isn't in the dataset, submit it as a URL and it is resolved. We provide a file for you to be able to do so.
###### - Timestamped 'results' and 'failure' csv output files. FTW.
######  - A smart layout that allows sorting in a non-destructive fashion. 

######  - Automatic 'backoff and retry' that can handle the VT Rate limiter (currently a 20 second pause every 4 records when using a public API key) and make it your best friend.
######  - VTMG can be installed locally or on the server of your choice

The config file allows you to set 

1. 	The wait-time between queries to control network usage. If left alone, VTMG could happily eat them all. In a good way.
2. The maximum total amount of time to retry before failing a query. Trust me on this, you want control. 
3. ... all sorts of other stuff like the home path in server mode
	 
## Requirements
- Internet access (duh?)
- Python 3.6 or higher
- A VirusTotal [Account](https://www.virustotal.com/#/join-us)
- A VirusTotal [APIkey](https://www.virustotal.com/#/settings/apikey)
- The following MIT-licensed 3rd-party Python modules:
    - The excellent `arrow`, for better time handling than the built-in Python modules
    - The equally excellent `riprova`, which implements backoff and retry as a decorator as if it were born to do so.
    - The superlative `tqdm`, which makes all the progress VTMG makes visible for all to see.
    - `dnspython`, about which we mercifully have no comment
    - And finally, the stalwart `urlquick` (because `requests` is not MIT licensed)

# Installation

## Basic instructions

0) If you used the previous version of this tool simply called VirusTotal Batch, delete everything. Throw your computer away, reject all technology, become a Buiddhst monk> But most importantly, these files
	vtbatch.py	vtconfig.py	dns_https.py

But seriously? Ditch it all. Material goods will be our downfall. Learn an artform and create something. In the meantime ...

1) Create the following directories
	/input
	/logs
	/program
	/results/virustotal
	/support
	/temp/VT
	
	
2) Install these files into /program
'config.py''reno.py'
'vtmachinegun.py'
'vtmgfunctions.py' 


3) Create a file named `VTlookup.txt` and place it in /input

4) Edit `config.py` and replace `put_APIKEY_here` with your own APIKey, and optionally, tweak the other parameters. See if we care.
																																																																																																																																																																																																																																																	5) Install `urlquick`, `arrow`, `tqdm`, `dnspython`, and `riprova`. Do it now. you know you wanna.

6) Run the program and **enjoy** the ferocious power of VT Machine Gun. We made it for the likes of you.

## server_mode

Change `server_friendly = 'no'` into `server_friendly = 'yes'`

Set a home path. This is the directory in which VTMG will look for the `VTLookup.txt` file to process, and to which it will save zipped results and errors files.

The program logs results and errors, the output has a timestamp & username in the filename.


## Apple OSX users

*OUTDATED The information that follows is not the best way to do this. We will update this text shortly*: If you are on OSX, be aware that the python.org installer installs its own version of OpenSSL that will not access the system certificates. This will cause OpenSSL to reject the VirusTotal certificate, which in turn will cause the program to fail.

If Python 3.6 *IS NOT* yet installed, install both Python 3.6 and OpenSSL with [homebrew](https://brew.sh).


If Python 3.6 *IS* installed we need to know if it has been installed using homebrew or using the python.org installer.

1) Open a terminal and type: `brew list`.

2) If you see "python3" in the list, type `brew install openssl` and you are done. Do not perform anymore steps.

3) If you *do not* see "python3" in the list, Python was not installed using brew and you need to copy the system certificates.

4) Find the Python 3.6 Folder and open it. Double click on `Install Certificates.command`

5) In Terminal type (or copy/paste) the lines below:

    cd Applications/Python\ 3.6
    sudo ./Install\ Certificates.command

6) All done - Please note: you still will not see Python in `brew list` after doing this.

## Known Bugs 
1) A resolutions against CNAME hosts at `Bodis` and `Wildcard UK Limited` come back erroneously in the results file. We're working on it. 


## License (MIT)
Copyright (c) 2018 Adam Z. Wasserman, Neil Schwartzman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.