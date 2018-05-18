# VTB (VirusTotal Batch Processer)
VTB is a command line program for  anyone who uses VirusTotal for mass lookups (or submissions) of domain names, IPs, and urls.

## Notable Features

 - IP addresses can be input individually or as CIDR notation
 -  VTB optionally performs live A resolutions in conjunction with Passive DNS data 
- Timestamped 'results' and 'failure' csv output files
 - A "sane" columnar layout
 - Expansion of VT results into multiple rows allowing for sorting and other data manipulation in a non-destructive manner
 - Automatic 'backoff and retry' to allow for the VT Rate limiter (currently a 20 second pause every 4 records when using a public API key)
 - Operates locally or on the server of your choice
 - The config file allows you to set all of the below:
	 - your API Key (mandatory)
	 - wait-time between queries (to control network usage)
	 - maximum total amount of time (in seconds) to retry before failing a query
	 - "server_mode" (see below)
	 - home path (needed for server mode)

## Requirements
- Internet access.
- Python 3.6 or higher.
- A VirusTotal [Account](https://www.virustotal.com/#/join-us)
- A VirusTotal [APIkey](https://www.virustotal.com/#/settings/apikey)
- The following MIT licensed 3rd party python modules:
    - The excellent `arrow` for better time handling than the built-in python modules
    - The equally excellent `riprova` which implements backoff and retry as a decorator (easy-peasy)
    - The superlative `tqdm` which makes all progress visible 
    - And finally the stalwart `urlquick`, because `requests` is not MIT licensed 

# Installation

##Basic instructions

1) Install the four python files (`vtbatch.py`, `vt_functions.py`, `vtconfig.py`, `dns_https.py`) in the directory of your choosing.

2) Install `urlquick`, `arrow`, `tqdm`, and `riprova`.

3) Edit the `config.py` file and replace `put_APIKEY_here` with your own APIKey, optionally change other params.

4) Make sure there is a file named `VTlookup.txt` in the same directory as the program.

5) Run the program, feel the power.

##server_mode

Change `server_friendly = 'no'` into `server_friendly = 'yes'`

Set a home path. This is the directory in which VTBatch will look for the `VTLookup.txt` file to process, and to which it will save zipped results and errors files.

The program will also log results and errors to files on the server wich have timestamp and username in the filename.


##Macintosh users

If you are on a Macintosh, be aware that the python.org installer installs its own
version of OpenSSL that will not access the system certificates. This will cause OpenSSL to
reject the VirusTotal certificate, which in turn will cause the program to fail.

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
