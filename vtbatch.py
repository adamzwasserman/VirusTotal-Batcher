# VTB 1.2.3 May 17, 2018

# Python 3.6 modules
import csv
import sys
import getpass
import warnings
from pathlib import Path

# MIT licensed 3rd party modules
import arrow
from tqdm import tqdm, TqdmSynchronisationWarning
from dns_https import SecureDNS  # Is not installed with pip. The file is included with this distro.


# Import functions from vt_function.py to validate types and perform lookups
import vt_functions as vt
# Import config data and grab at_api_key
import vtconfig as cfg


# Globals
domain_lookup_results = []
forced_results = []
url_lookup_results = []
ip_lookup_results = []


# Main program

# make sure the config file is present,
# and if in server friendly mode that the home path is properly set and...
# the lookup file is in the proper place.
try:
    server_mode = cfg.server_friendly
    if server_mode is 'no':
        home = ''
        source_file_error = "\n\n" \
                            "***WARNING*** You must have a file named 'Vtlookup.txt' in the same directory as " \
                            "the program files vtbatch.py and vt_functions.py" \
                            "\n\n"
    else:
        home = str(Path.home()) + cfg.home_path  # change in config.py
        source_file_error = "\n\n" \
                            "***WARNING*** You must have a file named 'Vtlookup.txt' in the path that is specified " \
                            "in your vtconfig.py file" \
                            "\n\n"
except:
    print("\n\n"
          "***WARNING*** Please setup the program properly by making sure the vtconfig.py file is in the same "
          "directory as vtbatch.py and vt_functions.py"
          "\n\n")
    sys.exit()

input_file = Path(home+'VTlookup.txt')
if not input_file.is_file():
    print(source_file_error)
    sys.exit()

# Prompt the user to choose what kind of lookup to perform
while True:
    try:
        filetype = int(
            input("\n\n"
                  "Welcome to VTBatch version 1.2.3\n"
                  "Make sure that VTlookup.txt contains ONLY one of these types of data:\n"
                  "    Domain names  (no lines start with http)\n"
                  "    URLS          (every line starts with http)\n"
                  "    IP addresses  (the program will accept CIDR notation)\n\n"
                  "(1) Domain and Host Name Lookup\n"
                  "(2) IP Address Lookup  (returns pDNS results)\n"            
                  "(3) URL Score Lookup\n"
                  "(4) Force URL Scoring\n\n"
                  "Please enter the number for the type of file (or 0 to quit): "))

    except ValueError:
        print('\n***Please type a number:***')
        continue

    if not filetype < 5:
        print('\nPlease enter the number for the type of file (or 0 to quit): ')
        continue

    elif filetype is 0:
        sys.exit()

    else:
        break

# Read in the file for processing
suspects = open(input_file, 'r')
list_to_process = [line.strip() for line in suspects]
suspects.close()

# Validate that the file has only one type of lookup value and report back to the user if there are problems
errors = 0
filetype_text = {1: 'a Domain Name', 2:'an IP Address', 3: 'a URL', 4: 'a URL'}
for index, lookup_value in enumerate(list_to_process):
    lookup_value = lookup_value.strip()
    try:
        if vt.is_ip(lookup_value) is True:
            if filetype is not 2:
                print("Line ", index + 1, lookup_value, " is an IP address, not", filetype_text.get(filetype))
                errors += 1

        elif vt.is_domain(lookup_value) is True:
            if filetype is not 1:
                print("Line ", index + 1, lookup_value, " is a Domain Name, not", filetype_text.get(filetype))
                errors += 1


        elif vt.is_url(lookup_value) is True:
            if filetype is not 3 and filetype is not 4:
                print("Line ", index + 1, lookup_value, " is a URL, not", filetype_text.get(filetype))
                errors += 1

        else:
            print("Line ", index + 1, ": (",lookup_value, ") is not a valid Domain Name or IP or URL")
            errors += 1
    except:
        print("There is something wrong with line ", index + 1, ".  ",lookup_value,"should contain ",filetype_text.get(filetype))

if errors > 0:
    print('\n***The', errors, 'lines above need to be corrected before this file can be processed***')
    exit()
else:
    print('Starting lookups...')


#  Set up the header row in the final_results list and tell the program which function to call for each case
if filetype is 1:
    domain_lookup_results = [('Query', 'Last pDNS', 'IP', 'Observed Subdomains','Live Resolution',
                              'Scan Date', 'Score', 'URL')]
    def lookup(domain):
        return vt.lookup_domains(domain)

elif filetype is 2:
    ip_lookup_results = [('Query', 'ASN', 'Last pDNS', 'Hostname', 'Live Resolution','Scan Date', 'Score', 'URL')]
    def lookup(ip):
        return vt.lookup_ips(ip)

elif filetype is 3:
    url_lookup_results = [('Query', 'Scan Date','Score', 'URL')]
    def lookup(url):
        return vt.lookup_urls(url)

elif filetype is 4:
    forced_results = [('Query', 'Scan Date', 'Status')]
    def lookup(url):
        return vt.force_urls(url)



#  Do the lookups
job_start_time_file = arrow.utcnow()
job_start_time_print = arrow.now()
outof = len(list_to_process)
error_list = [('Lookup Value', 'VT Error Message')]
hostname_count = 0
filetype_text = {1: 'Domain Names', 2:'IP Addresses', 3: 'URLs', 4: 'URLs'}

with warnings.catch_warnings():  # tqdm has a minor bug causing it throw warnings that would just confuse the user
    warnings.simplefilter("ignore", TqdmSynchronisationWarning)
    for item in tqdm(list_to_process, total= len(list_to_process), unit=" " + filetype_text.get(filetype)):
        # url is unused. I left it in in case we go back to the requirement of splitting urls into seperate files
        good, bad, url, count = lookup(item)
        domain_lookup_results.extend(good)
        url_lookup_results.extend(good)
        forced_results.extend(good)
        ip_lookup_results.extend(good)
        error_list.extend(bad)
        hostname_count += count

job_finish_time = arrow.now()

if hostname_count/4 > 59:
    time_to_live_lookup =  str(round(hostname_count/4/60,1)) + ' minute(s)'
else:
    time_to_live_lookup = str(round(hostname_count/4,1))  + ' seconds'

livelookup = ''
if filetype < 3:
    while True:
        livelookup = (
                input("This lookup returned {} hostnames. Do you want to perform a live dns resolution on all of them? "
                      "It will take approximately {}.\nType y for yes or n for no:\n"
                      .format(hostname_count,time_to_live_lookup)))

        if livelookup is 'y':
            break

        elif livelookup is 'n':
            break

        else:
            continue

live = SecureDNS()
vt_live =''
if livelookup is 'y':
    live_start_file = arrow.utcnow()
    live_start_print = arrow.now()
    with warnings.catch_warnings():  # tqdm has a minor bug causing it throw warnings that would just confuse the user
        warnings.simplefilter("ignore", TqdmSynchronisationWarning)
        for index, record in tqdm(enumerate(domain_lookup_results),total=len(domain_lookup_results), unit=" live lookups"):
            if record[3] and index > 0:
                try:
                    vt_live = live.gethostbyname(record[3])
                except:
                    pass
                temp = list(record)
                temp[4] = vt_live
                record = tuple(temp)
                domain_lookup_results[index] = record
                ip_lookup_results[index] = record
                vt_live = ''

            elif filetype is 1 and record[2] and index > 0:
                try:
                    vt_live = live.gethostbyname(record[0])
                except:
                    pass
                temp = list(record)
                temp[4] = vt_live
                record = tuple(temp)
                domain_lookup_results[index] = record
                vt_live = ''

        job_finish_time_file = arrow.utcnow()
        job_finish_time_print = arrow.now()
        job_duration_file = vt.td_format(job_finish_time_file - job_start_time_file)
        job_duration_print = vt.td_format(job_finish_time_print - job_start_time_print)
        live_message_file = "This job started at : " + str(job_start_time_file.format('YYYY-MM-DD HH:mm:ss')) + \
                       " (UTC), live lookups started at : " + str(live_start_file.format('YYYY-MM-DD HH:mm:ss'))
        live_message_print = "This job started at : " + str(job_start_time_print.format('YYYY-MM-DD HH:mm:ss')) + \
                       ", live lookups started at : " + str(live_start_print.format('YYYY-MM-DD HH:mm:ss'))
        print("\n",live_message_print)
        domain_lookup_results.append([live_message_file])
        ip_lookup_results.append([live_message_file])

else:
    job_finish_time_print = arrow.now()
    job_duration_print = vt.td_format(job_finish_time_print - job_start_time_print)
    live_message_print = "This job started at : " + str(job_start_time_print.format('YYYY-MM-DD HH:mm:ss'))
    print("\n", live_message_print)

#  Write out a timestamped results file (excel flavoured csv)
if filetype is 1:
    csvname = home + "VT Domain Lookup Results " + arrow.now().format('YYYY-MM-DD HH-mm') + ".csv"
    with open(csvname, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(domain_lookup_results)
        csvfile.flush()
    csvfile.close()
    if server_mode is 'yes':
        csvname = "VT Domain Lookup Results " + arrow.now().format('YYYY-MM-DD HH-mm') + "-" + getpass.getuser() + ".csv"
        with open(csvname, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(domain_lookup_results)
            csvfile.flush()
        csvfile.close()

elif filetype is 3:
    csvname = home + "VT URL Lookup Results" + arrow.now().format('YYYY-MM-DD HH-mm') + ".csv"
    with open(csvname, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(url_lookup_results)
        csvfile.flush()
    csvfile.close()
    if server_mode is 'yes':
        csvname = "VT URL Lookup Results" + arrow.now().format('YYYY-MM-DD HH-mm') + "-" + getpass.getuser() + ".csv"
        with open(csvname, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(url_lookup_results)
            csvfile.flush()
        csvfile.close()

elif filetype is 4:
    csvname = home + "VT URL Forced Scan Results " + arrow.now().format('YYYY-MM-DD HH-mm') + ".csv"
    with open(csvname, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(forced_results)
        csvfile.flush()
    csvfile.close()
    if server_mode is 'yes':
        csvname = "VT URL Forced Scan Results " + arrow.now().format('YYYY-MM-DD HH-mm') + "-" + getpass.getuser() + ".csv"
        with open(csvname, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(forced_results)
            csvfile.flush()
        csvfile.close()

else:
    csvname = home + "VT IP Lookup Results " + arrow.now().format('YYYY-MM-DD HH-mm') + ".csv"
    with open(csvname, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(ip_lookup_results)
        csvfile.flush()
    csvfile.close()
    if server_mode is 'yes':
        csvname = "VT IP Lookup Results " + arrow.now().format('YYYY-MM-DD HH-mm') + "-" + getpass.getuser() + ".csv"
        with open(csvname, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(ip_lookup_results)
            csvfile.flush()
        csvfile.close()


#  Write out a timestamped error file (excel flavoured csv)
csvname = home + "VT Lookup Errors " + arrow.now().format('YYYY-MM-DD HH-mm') + ".csv"
with open(csvname, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile, dialect='excel')
    writer.writerows(error_list)
    csvfile.flush()
csvfile.close()
if server_mode is 'yes':
    csvname = "VT Lookup Errors " + arrow.now().format('YYYY-MM-DD HH-mm') + "-" + getpass.getuser() + ".csv"
    with open(csvname, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(error_list)
        csvfile.flush()
    csvfile.close()
