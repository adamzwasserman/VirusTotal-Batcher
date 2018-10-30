# version 1.5.4 May 29 2018

# Python 3.6 modules
import csv
import sys
import re
import os
import urllib
import zipfile
import asyncio
from pathlib import Path

# 3rd party modules
import arrow
from tqdm import tqdm, TqdmSynchronisationWarning
from tldextract import TLDExtract

# local modules
import reno
import vtmachinegun as vtm
import config as cfg

# Initialize global variables
version_info = (2, 0 ,7)
version = '.'.join(str(c) for c in version_info)
debug = 0
server_mode = cfg.server_friendly
starting_nameserver = ['b.root-servers.net.']  # passed as a list because subsequent recursive calls will be lists


if debug is 0:
    tqdm_silent = True
else:
    tqdm_silent = False


def banner():
    global version
    b = '''
      _____         __  __                             
     |  __ \       |  \/  |                            
     | |  | |______| \  / |_   _ _ __   __ _  ___ _ __ 
     | |  | |______| |\/| | | | | '_ \ / _` |/ _ \ '__|
     | |__| |      | |  | | |_| | | | | (_| |  __/ |   
     |_____/       |_|  |_|\__,_|_| |_|\__, |\___|_|   
                                        __/ |          
                                       |___/           \n
        Version {v} - Faster than a speeding lemur.
                 Made by NS and AZW
    '''.format(v=version)
    print(b)


def main():
    banner()
    home, input_file = check_required_files()
    user_choice = prompt_user()
    list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds = initialize_lists(input_file)
    domain_list, failure_list = munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds)
    if user_choice is 2:
        domain_list = a_lookup(domain_list)
        domain_list.insert(0,('Reportable Element','Abuse Contact','Live Resolution'))
    else:
        domain_list.insert(0, ('Reportable Element', 'Abuse Contact'))
    save_to_file(home, domain_list, home + "/results/dMunge/d-munged Hostnames" )
    if failure_list:
        failure_list.insert(0, ('Reportable Element', 'Alexa', 'SP List'))
        save_to_file(home, failure_list, home + "/results/dMunge/UN-munged Hostnames" )


def api(input_file):
    list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds = initialize_lists(input_file)
    domain_list, failure_list = munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds)
    return domain_list,failure_list


def check_required_files():
    # make sure the config file is present,
    # and if in server friendly mode that the home path is properly set and...
    # the lookup file is in the proper place.
    try:
        server_mode = cfg.server_friendly
        home = cfg.home_path
        source_file_error = "\n\n" \
                            "***ALERT*** You must have a file named 'dmunge.txt' in the input directory, infidel" \
                            "\n\n"
    except:
        print("\n\n"
              "***ALERT*** Nope. You have to have the config.txt file snuggled up beside dmunge.py, in the same directory"
              "in the program directory"
              "\n\n")
        sys.exit()

    input_file = Path(home+'/input/dmunge.txt')
    if not input_file.is_file():
        print(source_file_error)
        sys.exit()

    white_file = Path(home+'/support/white.txt')
    if not white_file.is_file():
        print("\n\n"
              "***ALERT*** Nu-uh. Is the file white.txt in the /support/ directory, like we asked? Noooo, you wouldn't listen"
              "\n\n")
        sys.exit()

    splist_file = Path(home+'/support/splist.csv')
    if not splist_file.is_file():
        print("\n\n"
              "***ERROR*** You got to make sure the file splist.csv is in the /support/ directory, otherwise this isn't gonna work out"
              "directory as dmunge.py"
              "\n\n")
        sys.exit()

    alexa_file = Path(home + '/support/top-1m.csv')
    if not alexa_file.is_file():
        print("Downloading new Alexa Top 1M...")
        new_alexa_1m(home)

    home = cfg.home_path
    return home, input_file

def new_alexa_1m(home):
    with urllib.request.urlopen('http://s3.amazonaws.com/alexa-static/top-1m.csv.zip') as \
        response, open(home + '/support/top-1m.csv.zip', 'wb') as out_file:
        data = response.read()  # a `bytes` object
        out_file.write(data)
    print('Unzipping...')
    with zipfile.ZipFile(home + '/support/top-1m.csv.zip', 'r') as zip_ref:
        zip_ref.extractall(home + '/support/')

def prompt_user():
    # Display menu to allow user to update TLDs or exit program
    home = cfg.home_path
    tldcache = home + '/support/tldcache'
    while True:
        try:
            user_choice = int(
                input("\nThis program will look for a file in your home directory named dmunge.txt. \n"
                      "For each line, it will attempt to extract a hostname and save it to the *Results* file.\n"
                      "If it is unable to extract a hostname, the line will be saved to the *Unprocessed* file.\n\n"     
                      "Please enter 1 to D-Mungify, 2 to D-Mungify with Live Resolution or 0 to quit: "))
        except ValueError:
            print('\n***Please type a number:***')
            continue

        if not user_choice < 4:
            print('\nPlease enter 1 to continue (or 0 to quit): ')
            continue

        elif user_choice is 3:
            # Force a redownload of the tld list
            print("Downloading new Public Suffix List...")
            os.remove(home + '/support/tldcache')
            xtract_domain = TLDExtract(
                cache_file=tldcache, include_psl_private_domains=True)('apple.com')

            # Force a redownload of the Alexa Top 1M
            print("Downloading new Alexa Top 1M...")
            new_alexa_1m(home)
            continue

        elif user_choice is 0:
            sys.exit()

        else:
            break
    return user_choice


def initialize_lists(input_file):
    home = cfg.home_path
    a1m =    home + '/support/top-1m.csv'
    white = home + '/support/white.txt'
    sp =    home + '/support/splist.csv'
    print("Loading the Alexa Top 1M to memory...")

    alexadict = dict([tuple(line.strip().split(','))
                      for line in tqdm(open(a1m, 'r'),
                                       total=1000000, unit=" lines read", disable=tqdm_silent)
                      if '#' not in line])

    print("Setting up the other lists...")
    alexa_top_1m = set(list(alexadict.values()))
    list_to_process = [line.strip() for line in open(input_file, 'r')]
    list_to_process = [item.split() for item in list_to_process]
    list_to_process = [item for sublist in list_to_process for item in sublist]
    whitelist = set([line.strip() for line in open(white, 'r')])
    service_providers = dict([tuple(line.strip().split(','))
                              for line in open(sp, 'r')
                              if '#' not in line])
    extended_tlds = list(service_providers.keys())

    return list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds


def munge(list_to_process, whitelist, alexa_top_1m, service_providers, extended_tlds):
    print("\nMunging...")

    home = cfg.home_path
    tldcache = home + '/support/tldcache'
    job_start = arrow.now()
    xtract_domain = TLDExtract(cache_file=tldcache, include_psl_private_domains=True, extra_suffixes=extended_tlds)
    domains = []          # log successful reductions
    failures = []         # log failures
    already_seen = set()  # Check to make sure we do not return the same domain twice.


    for i, line in \
            tqdm(enumerate(list_to_process), total = len(list_to_process), unit=" lines munged", disable=tqdm_silent):
        extracted = xtract_domain(line)
        domain = extracted.registered_domain
        tld = extracted.suffix

        if domain and tld:
            if domain in whitelist:
                reason_code = "Whitelist"
                failures.append((line, reason_code))

            elif domain in alexa_top_1m:
                reason_code = "Alexa"
                failures.append((line, reason_code))

            elif domain not in already_seen:
                try:
                    service_provider = service_providers[tld.lower()]
                except:
                    service_provider = "~none"

                domains.append((domain, service_provider))
                already_seen.add(domain)

        elif tld:
            if tld not in already_seen:
                already_seen.add(tld)

            reason_code = "tld only, no domain"
            failures.append((tld, reason_code))

        elif '://' in line:
            ip = re.findall(r'\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?', line)
            try:
                if ip[0] not in already_seen:
                    reason_code = "IP address"
                    domains.append((ip[0], reason_code))
                    already_seen.add(ip[0])
                else:
                    pass
            except:
                pass

        else:
            reason_code = "No domain info"
            failures.append((line, reason_code))

    domain_list = list(set(domains))
    domain_list.sort(key=lambda elem: (elem[1], elem[0].split('.')[::-1], elem[0]))

    failure_list = list(set(failures))
    failure_list.sort(key=lambda elem: (elem[1], elem[0].split('.')[::-1], elem[0]))

    job_finish = arrow.now()
    print(" ")
    print("Ended run at: ", arrow.now().format('YYYY-MM-DD HH:mm:ss'), "and took ", (job_finish - job_start), "to run.")

    return domain_list, failure_list


def a_lookup(domain_list):
    domain_only_list = [domain for domain, service_provider in domain_list]

    # Call the multi-process async loop to resolve each hostname and validate that we received results
    resolutions = loop.run_until_complete(vtm.dnsloop(domain_only_list, 'the dMunged results'))
    try:
        resolutions_dict = dict(resolutions)
    except Exception as e:
        print(e, ' : ', resolutions)
        sys.exit()

    # Now step though the original VT results, and use each hostname as an index to grab its resolution
    # Replace the line(a tuple) with a new tuple that contains the resolved ip results
    for i, line in enumerate(domain_list):
        hostname = line[0].strip()
        try:
            host_ip = resolutions_dict[hostname]
            tuplist = list(line)
            tuplist.append(host_ip)
            domain_list[i] = tuple(tuplist)
        except:
            if hostname:
                host_ip = 'No result from Reno'
                tuplist = list(line)
                tuplist.append(host_ip)
                domain_list[i] = tuple(tuplist)

    return domain_list
    # live or dead, ip, timestamp


def save_to_file(home, some_list_of_tuples, filename):
    csvname = filename + " " + arrow.now().format('YYYY-MM-DD HH-mm-ss') + ".csv"
    zipname = filename + " " + arrow.now().format('YYYY-MM-DD HH-mm-ss') + ".zip"

    if server_mode is 'yes':
        print("Logging reduced hostnames to server...")

        with open(csvname, 'w') as out:
            csv_out = csv.writer(out)
            for row in some_list_of_tuples:
                csv_out.writerow(row)
        with zipfile.ZipFile(zipname, 'w') as myzip:
            myzip.write(csvname, os.path.basename(csvname))
        os.remove(csvname)

    else:
        with open(csvname, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect='excel')
            writer.writerows(some_list_of_tuples)
            csvfile.flush()

if __name__ == '__main__':
    # sys.exit(main(sys.argv)) # used to give a better look to exists
    loop = asyncio.get_event_loop()
    main()
    loop.close()

