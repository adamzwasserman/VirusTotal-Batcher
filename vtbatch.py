#  Python 3.6 modules
import csv

#  MIT licensed 3rd party modules
import arrow

#  import functions from vt_function.py to validate types and perform lookups
import vt_functions as vt

#  Globals
final_results = []

#  Main program
#  Prompt the user to choose what kind of lookup to perform
while True:
    try:
        filetype = int(
            input("\n\nYou MUST have a file named VTlookup.txt in the same folder as the VTLookup.py program. \n"
                  "The file MUST be one of the three types below: \n\n"
                  "(1) Domain Names             **(no http:// or https:// on any of the lines)\n"
                  "(2) URLs (lookup)            **(all lines must start with http:// or https://)\n"
                  "(3) URLs (force a scan)      **(all lines must start with http:// or https://)\n"
                  "(4) IP Addresses             **(only IP addresses; 'slash' notation is allowed, e.g. 192.168.0.0/16)\n\n"
                  "Please enter the number for the type of file: "))
    except ValueError:
        print('\n***Please type a number: 1, 2, or 3***')
        continue

    if not filetype < 5:
        print('\n***Please type a number: 1, 2, or 3***')
        continue

    else:
        break

#  Read in the file for processing
suspects = open('VTlookup.txt', 'r')
list_to_process = [line.strip() for line in suspects]
suspects.close()

#  Validate that the file has only one type of lookup value and report back to the user if there are problems
errors = 0
filetype_text = {1: 'a Domain Name', 2: 'a URL', 3: 'an IP Address'}
for index, lookup_value in enumerate(list_to_process):
    lookup_value = lookup_value.strip()

    try:
        if vt.is_ip(lookup_value) is True:
            if filetype is not 4:
                print("Line ", index + 1, lookup_value, " is an IP address, not", filetype_text.get(filetype))
                errors += 1

        elif vt.is_url(lookup_value) is True:
            if filetype is not 2 and filetype is not 3:
                print("Line ", index + 1, lookup_value, " is a URL, not", filetype_text.get(filetype))
                errors += 1

        elif vt.is_domain(lookup_value) is True:
            if filetype is not 1:
                print("Line ", index + 1, lookup_value, " is a Domain Name, not", filetype_text.get(filetype))
                errors += 1

        else:
            print("Line ", index + 1, ": (",lookup_value, ") is not a valid Domain Name or IP or URL")
            errors += 1
    except:
        print("There is something wrong with line ", index + 1, ". It contains: (",lookup_value,") and it should contain ",filetype_text.get(filetype))


if errors > 0:
    print('\n***The', errors, 'lines above need to be corrected before this file can be processed***')
    exit()
else:
    print('Starting lookups...')

#  Logic block
#  Reads filetype to determine how to setup the query to VT

#  Layout setup for selected query type.
#  Sets up the first item in final_results list as a header row with the proper titles.
#  Sets up the var "spacer"" to add a blank line between queries in domain and IP layouts.

#  Declares function lookup() and loads it with the actual function call for the type.
#  This way all logic is kept here, main loop has no logic, just always calls lookup().

if filetype is 1:
    final_results = [('Lookup Value', 'VT Result Status', 'IP', 'Date', 'Observed Subdomains', 'URLs', 'Score')]
    spacer = [('', '', '', '', '', '', '')]
    def lookup(domain):
        return vt.lookup_domains(domain)

elif filetype is 2:
    final_results = [('Lookup Value', 'Score', 'Date', 'VT Result Status', 'URL')]
    spacer = []
    def lookup(url):
        return vt.lookup_urls(url)

elif filetype is 3:
    final_results = [('Lookup Value', 'Score', 'Date', 'VT Result Status', 'URL')]
    spacer = []
    def lookup(url):
        return vt.force_urls(url)

elif filetype is 4:
    final_results = [('Lookup Value', 'VT Result Status', 'Date', 'A Record', 'URLs', 'Score')]
    spacer = [('', '', '', '', '', '')]
    def lookup(ip):
        return vt.lookup_ips(ip)

#  Do the lookups
job_start_time = arrow.now()
outof = len(list_to_process)
error_list = []

#  Main loop
for index, item in enumerate(list_to_process):
    print('Looking up ', index + 1, 'out of', outof, ':', item)
    good, bad = lookup(item)
    final_results.extend(good)
    final_results.extend(spacer)
    error_list.extend(bad)

job_finish_time = arrow.now()
print("Ended job at: ", arrow.utcnow().format('YYYY-MM-DD HH:mm:ss'), "and took ",
      vt.td_format(job_finish_time - job_start_time), "to run.")
#  Lookups completed

#  Write out a timestamped results file (excel flavoured csv)
csvname = "VT Lookup Results " + arrow.now().format('YYYY-MM-DD HH-mm-a') + ".csv"
with open(csvname, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile, dialect='excel')
    writer.writerows(final_results)
    csvfile.flush()
csvfile.close()

#  Write out a timestamped error file (excel flavoured csv)
csvname = "VT Lookup Errors " + arrow.now().format('YYYY-MM-DD HH-mm-a') + ".csv"
with open(csvname, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile, dialect='excel')
    writer.writerows(error_list)
    csvfile.flush()
csvfile.close()
