# Python 3.6 modules
import sys
import os
import concurrent.futures
import gc
from pathlib import Path
import asyncio
import csv

# MIT licensed 3rd party modules
import ipaddress
import arrow
from tqdm import tqdm

# Import functions from vt_function.py to validate types and perform lookups
import vtmgfunctions as fn
import reno

# Import config data and grab at_api_key
import config as cfg

# VirusTotal Batch - Machine Gun
version_info = (2, 0, 8)
version = '.'.join(str(c) for c in version_info)

# Globals
domain_lookup_results = []
forced_results = []
url_lookup_results = []
ip_lookup_results = []
temp_files = ['/temp/VT Domain-pDNS Results.txt',
              '/temp/VT IP-pDNS Results.txt',
              '/temp/VT URL-Lookup Results.txt',
              '/temp/VT URL-Submission Results.txt']


def main():
    banner()
    input_file = validate_required_files()  # Make sure that the environment is properly set up
    filetype = user_prompt()  # Interact with the user to get info on the job to be run
    list_to_process = prepare_lookup(filetype, input_file)  # Read in input files and create list memory to process
    do_vt_lookups(list_to_process, filetype)  # Query VirusTotal, and optionally do live resolutions
    file_cleanup(filetype)  # write results to disk (see comment in function about ips)


# welcome the user
def banner():
    global version
    b = '''

 _   _ _               _____     _        _  ______       _       _     
| | | (_)             |_   _|   | |      | | | ___ \     | |     | |    
| | | |_ _ __ _   _ ___ | | ___ | |_ __ _| | | |_/ / __ _| |_ ___| |__  
| | | | | '__| | | / __|| |/ _ \| __/ _` | | | ___ \/ _` | __/ __| '_ \ 
\ \_/ / | |  | |_| \__ \| | (_) | || (_| | | | |_/ / (_| | || (__| | | |
 \___/|_|_|   \__,_|___/\_/\___/ \__\__,_|_| \____/ \__,_|\__\___|_| |_|


___  ___           _     _              _____                           
|  \/  |          | |   (_)            |  __ \                          
| .  . | __ _  ___| |__  _ _ __   ___  | |  \/_   _ _ __                
| |\/| |/ _` |/ __| '_ \| | '_ \ / _ \ | | __| | | | '_ \               
| |  | | (_| | (__| | | | | | | |  __/ | |_\ \ |_| | | | |              
\_|  |_/\__,_|\___|_| |_|_|_| |_|\___|  \____/\__,_|_| |_|\n

    Version {v} Let's fight some crime!
             Made by NS and AZW
    '''.format(v=version)
    print(b)


# utility function to make sure that we clean up any files that may have left behind by interrupting a run
def remove_temp_files():
    home = cfg.home_path
    for file in temp_files:
        try:
            os.remove(home + file)
        except:
            pass


# Make sure that the environment is properly set up
def validate_required_files():
    try:
        home = cfg.home_path
        source_file_error = "\n\n***WARNING*** You must have a file named 'Vtlookup.txt' in {}/input/\n\n".format(
            cfg.home_path)
    except:
        print("\n\n"
              "***WARNING*** Please place the config.py file in"
              "the same directory as vtmachinegun.py"
              "\n\n")
        sys.exit()

    input_file = Path(home + '/input/VTlookup.txt')
    if not input_file.is_file():
        print(source_file_error)
        sys.exit()

    remove_temp_files()

    return input_file


# Interact with the user to get info on the job to be run
def user_prompt():
    while True:
        try:
            filetype = int(
                input("\n\n"
                      "VTlookup.txt must only have one type of data in it at a time:\n\n"    
                      "(1) Domain and Host Name  No entries with http:// or https://\n"
                      "                          [Results: IPs, sub-domains, and URLs with a VT score of 1 or more]\n"
                      "                          [Optionally, the current resolution of all resulting hosts]\n\n"
                      "(2) IP Addresses          Individual IPs or in CIDR Notation\n"
                      "                          [Results: Hosts and URLs]\n"
                      "                          [Optionally, the current resolution of all hosts]\n\n"
                      "(3) URL Score             All entries *must* start with http:// or https://\n"
                      "                          [Results: URLs with their current VT score\n\n"
                      "(4) Force URL Scoring     All entries *must* start with http:// or https://\n"
                      "                          [WARNING: All URLs are scanned, or re-scanned if previously submitted]\n"
                      "                          [WARNING: This may change historical scores positively, or negatively]\n"
                      "                          [Results: Confirmation of submission, no scores]\n\n"
                      "Please enter the number for the type of file (or 0 to quit): "))

        except ValueError:
            print('\n***Please type a number:***')
            continue

        if not filetype < 5:
            print('\nPlease enter the corresponding number of your query file (or 0 to quit): ')
            continue

        elif filetype is 0:
            sys.exit()

        else:
            break

    return filetype


# Read in input files and create list memory to prcess
def prepare_lookup(filetype, input_file):
    # Read in the file for processing
    suspects = open(input_file, 'r')
    list_to_process = [line.strip() for line in suspects]
    list_passed = []
    list_failed = []

    suspects.close()

    # Validate that the file has only one type of lookup value and report back to the user if there are problems
    errors = 0
    filetype_text = {1: 'a Domain Name', 2: 'an IP Address', 3: 'a URL', 4: 'a URL'}
    for index, lookup_value in enumerate(list_to_process):
        lookup_value = lookup_value.strip()
        try:
            if fn.is_ip(lookup_value) is True:
                if filetype is not 2:
                    print("Line ", index + 1, lookup_value, " is an IP address, not", filetype_text.get(filetype))
                    errors += 1
                    list_failed.append(lookup_value)
                else:
                    list_passed.append(lookup_value)

            elif fn.is_domain(lookup_value) is True:
                if filetype is not 1:
                    print("Line ", index + 1, lookup_value, " is a Domain Name, not", filetype_text.get(filetype))
                    errors += 1
                    list_failed.append(lookup_value)
                else:
                    list_passed.append(lookup_value)

            elif fn.is_url(lookup_value) is True:
                if filetype is not 3 and filetype is not 4:
                    print("Line ", index + 1, lookup_value, " is a URL, not", filetype_text.get(filetype))
                    errors += 1
                    list_failed.append(lookup_value)
                else:
                    list_passed.append(lookup_value)

            else:
                print("Line ", index + 1, ": (", lookup_value, ") is not a valid Domain Name or IP or URL")
                errors += 1
                list_failed.append(lookup_value)

        except:
            print("Cannot run job, there is an unsubmittable value in line ", index + 1, ".  ",
                  lookup_value, "should contain ", filetype_text.get(filetype))
            list_failed.append(lookup_value)

            sys.exit()

    if errors > 0:
        print('\n***The', errors, 'lines above are not of the correct type for this job. They will be saved to a'
                                  'file labed UNPROCESSED***')
        filename = cfg.home_path + "/results/virustotal/VT-UNPROCESSED-lines-from-VTinput.txt-" + arrow.now().format(
            'YYYY-MM-DD-HH-mm') + ".csv"
        write_list(list_failed, filename)
        list_to_process = list_passed

    return list_to_process


# one individual recursive lookup of a domain name - a long running, blocking IO function - used for filetype 2 only
def lookup(hostname):
    a_record = reno.main(hostname)
    return str(a_record)


# wraps the above in an async function that uses await
async def get_result(executor, hostname):
    loop = asyncio.get_event_loop()
    a_record = await loop.run_in_executor(executor, lookup, hostname)
    return hostname, a_record


# Creates process pool and puts one async live resolution function call in the pool for each hostname
async def do_the_thing(hosts, label):
    # create the process pool
    with concurrent.futures.ProcessPoolExecutor(cfg.async_pool) as executor:
        # puts one async live resolution function call in the pool for each hostname as a future
        futures = [get_result(executor, hostname) for hostname in hosts]
        results = []

        # As futures are completed they are returned and the result can be obtained and appended to results
        # try:
        for i, future in enumerate(tqdm(asyncio.as_completed(futures),
                                        total=len(futures),
                                        desc='Resolving hostnames from {}'.format(label),
                                        ncols=80,
                                        unit=' results/second',
                                        dynamic_ncols=True)):
            results.append(await future)
        return results
        # except futures.TimeoutError:
        #     results.append('RETRY')
        #     return  results


# Scheduling the run in the asyncio event loop
async def dnsloop(hosts, label):
    resolutions = await do_the_thing(hosts, label)
    timeouts = [host for host, reso in resolutions if 'RETRY' in reso]
    resolutions = [(host, reso) for host, reso in resolutions if 'RETRY' not in reso]
    print('Iteration 1 had {} reso and {} timeouts'.format(len(resolutions), len(timeouts)))

    inital_timeouts = timeouts
    last_iteration_length = 1000000000
    i = 0

    if len(inital_timeouts) > 0 and len(resolutions) > 0 and len(timeouts) > 0 and last_iteration_length > 0:
        while len(inital_timeouts) / (len(inital_timeouts) + len(resolutions)) > cfg.max_timeout_ratio \
                and last_iteration_length \
                and len(timeouts) / last_iteration_length < 0.75 \
                and i < cfg.max_resolution_retries:
            print('Retrying timeouts')
            reprocess = timeouts
            new_resolutions = await do_the_thing(reprocess, label)
            resolutions.extend(new_resolutions)

            i += 1
            last_iteration_length = len(timeouts)
            if len(inital_timeouts) is 0 or len(resolutions) is 0 or len(timeouts) is 0 or last_iteration_length is 0:
                break
            try:
                timeouts = [host for host, reso in resolutions if 'RETRY' in reso]
                # print(timeouts)
                resolutions = [(host, reso) for host, reso in resolutions if 'RETRY' not in reso]
                print('Iteration {} had {} reso and {} timeouts'.format(i + 1, len(resolutions), len(timeouts)))

            except:
                break
    return resolutions


# This is the principle loop, the one the iterates over the input file and calls the right functions as per data type
def do_vt_lookups(list_to_process, filetype):
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[filetype - 1]
    job_start_print = arrow.now()  # start job timer
    print('Job started at {}'.format(job_start_print))
    remove_temp_files()  # remove all temp files that might have been left behind from previous runs

    # filetype = 1 are domain name lookups
    if filetype is 1:
        # call fn.lookup_domains within a process pool
        user_choice = (
            input("\nType 0 to bypass host resolution, or any other key to continue:\n"))
        lookup_results = run_in_process_pool(cfg.process_pool_size, fn.lookup_domains, list_to_process,
                                             'Domain Lookups', ' lookups/second')


        if not lookup_results:
            print('No results')
        if user_choice is not '0':
            label = 'Domains'
            total_resolutions, new_lookup_results = do_live_lookups(lookup_results, label, True)

            if new_lookup_results:
                # sort by IP, then by the resolution results, then by the hostname, then by the scan date
                lookup_results = sorted(new_lookup_results,
                                            key=lambda tup: ([-ord(c) for c in tup[0]], tup[6], tup[5], tup[4]))

                print("\n")  # insert a blank line inbetween the progress bars for the next lookup in the loop
                job_finish_print = arrow.now()
                job_duration_print = (job_finish_print - job_start_print)
                print("\n"
                      "{} live resolutions were performed at an average rate of {} per resolutions second"
                      .format(total_resolutions, round(total_resolutions / job_duration_print.seconds, 2)))

            # insert a header
            lookup_results.insert(0, (
                'Query', 'Last pDNS', 'pDNS Time', 'pDNS IP', 'Observed Subdomains', 'Live Resolution', 'Scan Date',
                'Scan Time', 'Score', 'URL'))

            write_list(lookup_results, temp_file)


    # filetype = 2 are IP address lookups (both single IPs and CIDR blocks)
    # live resolution is performed in a seperate async function because there are thousands of resolutions per vt result
    elif filetype is 2:
        user_choice = (
            input("\nType 0 to bypass host resolution, or any other key to continue:\n"))

        if user_choice is '0':
            live_resolve = 'no'
        else:
            live_resolve = 'yes'

        for ip in list_to_process:
            label = str(ip)  # create a label (progress bar and results file)
            cidr_blocks = []  # list to hold CIDR blocks before expansion
            cidr_blocks.extend(ipaddress.ip_network(ip, strict=False))  # converts input file to a list of CIDR blocks
            expanded_ips = [ip for ip in cidr_blocks]  # flattens CIDR blocks to a list of single IPs

            # first we run the vt queries on the ips, this will write a file to disk that contains a list of hostnames
            with concurrent.futures.ProcessPoolExecutor(cfg.process_pool_size) as executor:
                futures = [executor.submit(fn.lookup_ips, ip)
                           for ip in tqdm(expanded_ips, desc='Launching VT queries for {}'.format(label),
                                          ncols=80,
                                          total=len(expanded_ips),
                                          unit=' queries/second',
                                          dynamic_ncols=True)]
                for future in tqdm(concurrent.futures.as_completed(futures),
                                   desc='Collecting query results {}'.format(label),
                                   ncols=80,
                                   total=len(futures),
                                   unit=' results/second',
                                   dynamic_ncols=True):
                    pass

            try:
                results = open(temp_file, 'r')
                lookup_results = [line.split(',') for line in results]
                results.close()
                if not lookup_results:
                    print('No results')
            except:
                print('No results')
                results = False
                write_list([('No results',)],home + "/results/virustotal/" +
                      label + "-VT-pDNS-Results-" +
                      arrow.now().format('YYYY-MM-DD-HH-mm') + ".csv")
                continue

            if live_resolve is 'yes' and results:
                total_resolutions, new_lookup_results = do_live_lookups(lookup_results, label, False)
                if new_lookup_results:
                    # sort by IP, then by the resolution results, then by the hostname, then by the scan date
                    lookup_results = sorted(new_lookup_results,
                                                key=lambda tup: ([-ord(c) for c in tup[0]], tup[6], tup[5], tup[4]))

                    print("\n")  # insert a blank line inbetween the progress bars for the next lookup in the loop

                    job_finish_print = arrow.now()
                    job_duration_print = (job_finish_print - job_start_print)
                    print("\n{} live resolutions were performed at an average rate of {} per resolutions second".
                          format(total_resolutions,
                                 round(total_resolutions / job_duration_print.seconds,2)))

            # insert a header
            lookup_results.insert(0, ('Query', 'ASN', 'Last pDNS', 'pDNS Time', 'Hostname',
                                          'Live Resolution', 'Scan Date', 'Scan Time', 'Score', 'URL'))
            write_list(lookup_results, temp_file)

            # replace "/" from cidr block with '-' to avoid path problems
            if label[-3] is "/":
                label = label[:-3] + "--" + label[-2:]

            # rename results file with time stamp
            os.rename(temp_file,
                      home + "/results/virustotal/" +
                      label + "-VT-pDNS-Results-" +
                      arrow.now().format('YYYY-MM-DD-HH-mm') + ".csv")

    # filetype = 3 are url name lookups
    elif filetype is 3:

        # writing to disk so that if process is interrupted we have all results processed to that moment
        with open(temp_file, 'a') as f:
            f.write('Scan Date,Score,URL\n')

        # call fn.lookup_domains within a process pool
        run_in_process_pool(cfg.process_pool_size, fn.lookup_urls, list_to_process, 'URL Lookups',
                            ' lookups/second')


    # filetype = 1 are url submissions
    elif filetype is 4:
        forced_results = [('Query', 'Scan Date', 'Status')]

        # writing to disk so that if process is interrupted we have all results processed to that moment
        home = cfg.home_path
        with open(temp_file, 'a') as f:
            f.write('Query,Scan Date,Status\n')

        # call fn.lookup_domains within a process pool
        run_in_process_pool(cfg.process_pool_size, fn.force_urls, list_to_process, 'URL Submissions',
                            ' subs/second')

    # Print out  a job timer
    job_finish_print = arrow.now()
    job_duration_print = fn.td_format(job_finish_print - job_start_print)
    print("\nThis job finished at {} and took {}".format(job_finish_print, job_duration_print))
    # Reminder: Add count all live resos


def do_live_lookups(lookup_results, label, is_domain):
    # this function resolves hostnames to ips
    column_number = 4
    new_lookup_results = lookup_results
    total_resolutions = 0  # for reporting at job finish
    # Read in VT Lookup Results to process hostname resolutions, bail out if no file
    home = cfg.home_path
    if not lookup_results:
        return total_resolutions, False

    # "Uniquify" the hostnames to prevent unnecessary duplication of lookups (save cpu and bandwidth)
    hostnames = [line[column_number] for line in new_lookup_results if len(line[column_number]) > 1]
    if is_domain:
        domains = [line[0] for line in new_lookup_results if len(line[column_number]) < 1]
        hostnames.extend(domains)
    hostnames = sorted(list(set(hostnames)), key=lambda tup: tup[0])

    # Call the multi-process async loop to resolve each hostname and validate that we received results
    resolutions = loop.run_until_complete(dnsloop(hostnames, label))
    try:
        resolutions_dict = dict(resolutions)
        total_resolutions += len(resolutions)
    except Exception as e:
        print(e, ' : ', resolutions)
        sys.exit()

    # Now step though the original VT results, and use each hostname as an index to grab its resolution
    # Replace the line(a tuple) with a new tuple that contains the resolved ip results
    for i, line in enumerate(new_lookup_results):
        hostname = line[column_number].strip()

        # ignore lines that contain URLs
        if is_domain and not hostname:
            hostname = line[0].strip()
        try:
            host_ip = resolutions_dict[hostname]
            tuplist = list(line)
            tuplist[5] = host_ip
            new_lookup_results[i] = tuple(tuplist)
        except:
            if hostname:
                host_ip = 'Live resolution failed'
                tuplist = list(line)
                tuplist[5] = host_ip
                new_lookup_results[i] = tuple(tuplist)

    return total_resolutions, new_lookup_results


def run_in_process_pool(size, function, input_list, description, unit):
    results = []
    with concurrent.futures.ProcessPoolExecutor(size) as executor:
        futures = [executor.submit(function, single_param)
                   for single_param in tqdm(input_list,
                                            desc='Building job queue',
                                            ncols=80,
                                            total=len(input_list),
                                            unit='jobs',
                                            dynamic_ncols=True)]
        for future in tqdm(concurrent.futures.as_completed(futures),
                           desc=description,
                           ncols=80,
                           total=len(futures),
                           unit=unit,
                           dynamic_ncols=True):
            try:
                results.extend(future.result())
            except:
                pass
    return results


def file_cleanup(filetype):
    # write out to disk for filetypes 1,3,4. Filetype 2 is omitted because it has its own, more complicated write out
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[filetype - 1]
    filetype_text = {1: 'Domain-pDNS', 3: 'URL-Lookup', 4: 'URL-Submission'}

    if filetype is not 2:
        os.rename(temp_file,
                  home + "/results/virustotal/VT-" +
                  filetype_text[filetype] + "-Results-" +
                  arrow.now().format('YYYY-MM-DD-HH-mm') + ".csv")

def line_prepender(filename, line):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(line.rstrip('\r\n') + '\n' + content)

# write a list to file
def write_list(list_to_write, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(list_to_write)
        csvfile.flush()


if __name__ == '__main__':
    # sys.exit(main(sys.argv)) # used to give a better look to exits
    loop = asyncio.get_event_loop()
    main()
    loop.close()

