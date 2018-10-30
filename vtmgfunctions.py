#  Python 3.6 modules
import re
import ipaddress
import time
import urllib.request
import urllib.parse
import urllib.error
import json
import concurrent.futures
import functools

#  MIT licensed 3rd party modules
import arrow
import riprova
from tqdm import tqdm
import urlquick

import dns.name
import dns.message
import dns.query
import dns.flags
import dns.resolver

#  import config data and grab at_api_key
import reno
import config as cfg

# VirusTotal Batch Machine Gun
version_info = (2,0,7)
version = '.'.join(str(c) for c in version_info)

# Grab VirusTotal API key
api_key = cfg.api_key

max_timeout = 10
name_server_ip = '8.8.8.8'
temp_files = ['/temp/VT Domain-pDNS Results.txt',
              '/temp/VT IP-pDNS Results.txt',
              '/temp/VT URL-Lookup Results.txt',
              '/temp/VT URL-Submission Results.txt']

# A decorator to make a function async
_DEFAULT_POOL = concurrent.futures.ThreadPoolExecutor()


def threadpool(f, executor=None):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        return (executor or _DEFAULT_POOL).submit(f, *args, **kwargs)

    return wrap


@threadpool
def live_lookup(hostname):
    liveness = reno.main(hostname)
    return liveness


#  ***Tests to determine type of lookup value***
#  Is lookup_value an IP address?
def is_ip(lookup_value):
    try:
        if ipaddress.ip_network(lookup_value, strict=False) == ipaddress.ip_network(lookup_value, strict=False):
            return True
    except ValueError:
        return False


#  Is lookup_value a URL? (taken from Django, modified ot accept long TLDs)
def is_url(lookup_value):
    regex = re.compile(
        r'(^https?://)([^\/]+?\.)([^\/]+/?)(.+)', re.IGNORECASE)  # (http(s)://) (hostname) (domain name) (params)
    if lookup_value is not None and regex.search(lookup_value):
        return True


#  Is lookup_value a domain?
def is_domain(lookup_value):
    if len(lookup_value) > 255:
        return False
    if lookup_value[-1] == ".":
        lookup_value = lookup_value[:-1]  # strip exactly one dot from the right, if present
    regex = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(regex.match(x) for x in lookup_value.split("."))


#  ***Functions to perform the three different kinds of lookups, plus one to force VT to re-scan a URL***
#  Riprova error logger
def on_retry(err, next_try):
    # print('Error exception: {}'.format(err))
    # print('Next try in {}ms'.format(next_try))
    pass


#  Function to lookup Domains
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=20, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1),
    on_retry=on_retry)
def lookup_domains(domain):
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[0]
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': domain, 'apikey': api_key}
    domain_lookup_results = []

    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)

        try:
            response_json = json.loads(response)
            vt_status = response_json['verbose_msg']

            if response_json['response_code'] is 1:
                vt_last_resolved = vt_ip = vt_subdomain = vt_subdomain_time = vt_live = vt_live_time = vt_last_scanned = vt_url = vt_score = ''
                try:
                    if response_json['resolutions']:
                        i = 0
                        for _ in response_json['resolutions']:
                            vt_ip = response_json['resolutions'][i]['ip_address']
                            vt_last_resolved = response_json['resolutions'][i]['last_resolved'][:-9:]
                            vt_last_resolved_time = response_json['resolutions'][i]['last_resolved'][-8:]

                            with open(temp_file, 'a') as f:
                                f.write("{},{},{},{},{},{},{},{},{},{}\n"
                                        .format(domain, vt_last_resolved, vt_last_resolved_time, vt_ip, vt_subdomain,
                                                vt_live, vt_live_time, vt_last_scanned, vt_score, vt_url))

                            domain_lookup_results.append((domain,
                                                          vt_last_resolved,
                                                          vt_last_resolved_time,
                                                          vt_ip,
                                                          vt_subdomain,
                                                          vt_live,
                                                          vt_live_time,
                                                          vt_last_scanned,
                                                          vt_score,
                                                          vt_url))
                            i += 1
                except KeyError:
                    pass

                vt_last_resolved = vt_ip = vt_subdomain = vt_subdomain_time = vt_live = vt_live_time = vt_last_scanned = vt_url = vt_score = ''
                try:
                    if response_json['subdomains']:
                        for i in response_json['subdomains']:
                            vt_subdomain = i

                            with open(temp_file, 'a') as f:
                                f.write("{},{},{},{},{},{},{},{},{},{}\n"
                                        .format(domain, vt_last_resolved, vt_last_resolved_time, vt_ip, vt_subdomain,
                                                vt_live, vt_live_time, vt_last_scanned, vt_score, vt_url))

                                domain_lookup_results.append((domain,
                                                              vt_last_resolved,
                                                              vt_last_resolved_time,
                                                              vt_ip,
                                                              vt_subdomain,
                                                              vt_live,
                                                              vt_live_time,
                                                              vt_last_scanned,
                                                              vt_score,
                                                              vt_url))
                except KeyError:
                    pass

                vt_last_resolved = vt_ip = vt_subdomain = vt_subdomain_time = vt_live = vt_live_time = vt_last_scanned = vt_url = vt_score = ''
                try:
                    if response_json['detected_urls']:
                        for i in response_json['detected_urls']:
                            vt_url = i['url']
                            vt_last_scanned = i['scan_date'][:-9:]
                            vt_last_scanned_time = i['scan_date'][-8:]
                            vt_score = i['positives']

                            with open(temp_file, 'a') as f:
                                f.write("{},{},{},{},{},{},{},{},{},{}\n"
                                        .format(domain, vt_last_resolved, vt_last_resolved_time, vt_ip, vt_subdomain,
                                                vt_live, vt_last_scanned, vt_last_scanned_time, vt_score, vt_url))

                                domain_lookup_results.append((domain,
                                                              vt_last_resolved,
                                                              vt_last_resolved_time,
                                                              vt_ip,
                                                              vt_subdomain,
                                                              vt_live,
                                                              vt_last_scanned,
                                                              vt_last_scanned_time,
                                                              vt_score,
                                                              vt_url))

                except KeyError:
                    pass

                if not domain_lookup_results:
                    with open(home + '/results/virustotal/VT Domain - Not in VT - to submit as URL.txt', 'a') as f:
                        f.write("https://{}\n".format(domain))

            else:
                with open(home + '/results/virustotal/VT Domain - Not in VT - to submit as URL.txt', 'a') as f:
                    f.write("{},{},{}\n".format(domain, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))

        except:
            # print("***The VT server did not respond, retrying...***")
            pass


    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        with open(home + "/results/virustotal/VT Domain - HTTP ERRORS.txt", 'a') as f:
            f.write("{},{},{}\n".format(domain, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))

    return domain_lookup_results


#  Subroutine to step through "slash" IP networks (*** currently not used***)
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=20, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1),
    on_retry=on_retry)
def lookup_ips(vt_lookup_value):
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[1]
    list_to_return = []
    vt_asn = vt_last_resolved = vt_hostname = vt_last_scanned = vt_url = vt_score = ''
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': vt_lookup_value, 'apikey': api_key}

    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)
        try:
            response_json = json.loads(response)
        except:
            print("The server did not respond. The program will retry until the server starts responding again")

        response_json = json.loads(response)
        if response_json['response_code'] is 1:
            vt_asn = vt_last_resolved = vt_last_resolved_time = vt_hostname = vt_live = vt_last_scanned = \
                vt_last_scanned_time = vt_url = vt_score = ''
            try:
                if response_json['asn']:
                    vt_asn = response_json['asn']
            except KeyError:
                pass

            try:
                if response_json['resolutions']:
                    for record in response_json['resolutions']:
                        vt_last_resolved = record['last_resolved'][:-9:]
                        vt_last_resolved_time = record['last_resolved'][-8:]
                        vt_hostname = str(record['hostname'])
                        with open(temp_file, 'a') as f:
                            f.write("{},{},{},{},{},{},{},{},{},{}\n".format(
                                vt_lookup_value, vt_asn, vt_last_resolved, vt_last_resolved_time, vt_hostname, vt_live,
                                vt_last_scanned, vt_last_scanned_time, vt_score, vt_url))
            except KeyError:
                pass

            vt_hostname = vt_live = vt_last_resolved = vt_last_resolved_time = ''
            try:
                if response_json['detected_urls']:
                    for record in response_json['detected_urls']:
                        vt_last_scanned = record['scan_date'][:-9:]
                        vt_last_scanned_time = record['scan_date'][-8:]
                        vt_url = str(record['url'])
                        vt_score = str(record['positives'])
                        with open(temp_file, 'a') as f:
                            f.write("{},{},{},{},{},{},{},{},{},{}\n".format(
                                vt_lookup_value, vt_asn, vt_last_resolved, vt_last_resolved_time, vt_hostname, vt_live,
                                vt_last_scanned, vt_last_scanned_time, vt_score, vt_url))
            except KeyError:
                pass

        else:
            vt_status = response_json['verbose_msg']
            with open(home + '/results/virustotal/VT IP Lookup NOT IN VT.txt', 'a') as f:
                f.write("{},{},{}\n".format(vt_lookup_value, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))
        return

    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        with open(home + '/results/virustotal/VT IP - HTTP ERRORS.txt', 'a') as f:
            f.write("{},{},{}\n".format(vt_lookup_value, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))
        return


#  Function to lookup URLs
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=20, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1),
    on_retry=on_retry)
def lookup_urls(vt_lookup_value):
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[2]
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    if vt_lookup_value[-1::] is '/':
        parameters = {'apikey': api_key, 'resource': vt_lookup_value[:-1:]}
    else:
        parameters = {'apikey': api_key, 'resource': vt_lookup_value}

    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)

        try:
            response_json = json.loads(response)
        except:
            print("***The VT server did not respond, retrying...***")

        if response_json['response_code'] is 1:
            try:
                vt_score = response_json['positives']
                vt_date = response_json['scan_date']
                vt_url = response_json['url']
                # list_to_return = [(vt_lookup_value, vt_date, vt_score, vt_url)]
                with open(temp_file, 'a') as f:
                    f.write("{},{},{}\n".format(vt_date, vt_score, vt_url))

            except KeyError as vt_status:
                with open(home + '/results/virustotal/VT URL Lookup NOT IN VT.txt', 'a') as f:
                    f.write("{},{},{}\n".format(vt_lookup_value, response_json['verbose_msg'],
                                                arrow.now().format('YYYY-MM-DD HH-mm')))

        else:
            vt_status = response_json['verbose_msg']
            # error_to_return = [(vt_lookup_value, vt_status)]
            with open(home + '/results/virustotal/VT URL Lookup NOT IN VT.txt', 'a') as f:
                f.write("{},{},{}\n".format(vt_lookup_value, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))

    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        # error_to_return = [(vt_lookup_value, vt_status)]
        with open(home + '/results/virustotal/VT URL - HTTP ERRORS.txt', 'a') as f:
            f.write("{},{},{}\n".format(vt_lookup_value, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))

    # return list_to_return, error_to_return, returned_urls, hostname_count
    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        with open(home + '/results/virustotal/VT URL - HTTP ERRORS.txt', 'a') as f:
            f.write("{},{},{}\n".format(vt_lookup_value, vt_status, arrow.now().format('YYYY-MM-DD HH-mm')))
    return


#  Function to force-lookup URLs
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=20, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1),
    on_retry=on_retry)
def force_urls(vt_lookup_value):
    fired_url = burn_with_fire(vt_lookup_value)
    home = cfg.home_path
    temp_file = cfg.home_path + temp_files[3]
    time.sleep(cfg.request_wait)

    url = 'https://www.virustotal.com/vtapi/v2/url/scan'

    if fired_url[-1::] is '/':
        parameters = {'apikey': api_key, 'url': fired_url[:-1:]}
    else:
        parameters = {'apikey': api_key, 'url': fired_url}

    data = urllib.parse.urlencode(parameters)
    data = data.encode('UTF-8')

    response = urllib.request.Request(url, data)

    with urllib.request.urlopen(response) as response:
        the_page = response.read()
        response_json = json.loads(the_page)

    if response_json['response_code'] is 1:
        vt_status = response_json['verbose_msg']
        vt_date = ''

        try:
            vt_date = response_json['scan_date']
        except KeyError:
            pass

        # list_to_return = [(vt_lookup_value, vt_date, vt_status)]
        with open(temp_file, 'a') as f:
            f.write("{}, {}, {}\n"
                    .format(fired_url, vt_date, vt_status))

    else:
        vt_status = response_json['verbose_msg']
        # error_to_return = [(vt_lookup_value, vt_status)]
        with open(home + '/results/virustotal/VT URL Submission ERRORS.txt', 'a') as f:
            f.write("{},{},{}\n".format(fired_url), vt_status, arrow.now().format('YYYY-MM-DD HH-mm'))

    return


#  Function to lookup IPs
def convert_slash_ips(passed_value):
    lookup_list = ipaddress.ip_network(passed_value, strict=False)  # expands CIDR to IPs, no effect on single IPs
    for vt_lookup_value in tqdm(lookup_list, total=len(list(lookup_list)), unit=" IPs from a CIDR block"):
        convert_slash_ips(vt_lookup_value)  # Call subroutine, it writes results to disk asynchronously
    return


# Redaction of emails
def burn_with_fire(submitted_url):
    search_pattern = re.compile(
        "(userid\=)*[a-zA-Z0-9\!\#\$\%\'\*\+\-\^\_\`\{\|\}\~\.]+@(?!(\w+\.)*(jpg|png))(([\w\-]+\.)*([\w\-]+))|"
        "[a-zA-Z0-9\!\#\$\%\'\*\+\-\^\_\`\{\|\}\~\.]+\%40(?!(\w+\.)*(jpg|png))(([\w\-]+\.)*([\w\-]+))")

    redacted_url = re.sub(search_pattern, r'\1email@example.com', submitted_url)
    return redacted_url


#  A little date formatter for pretty printing the job timer
def td_format(td_object):
    seconds = int(td_object.total_seconds())
    periods = [
        ('year', 60 * 60 * 24 * 365),
        ('month', 60 * 60 * 24 * 30),
        ('day', 60 * 60 * 24),
        ('hour', 60 * 60),
        ('minute', 60),
        ('second', 1)
    ]

    strings = []
    for period_name, period_seconds in periods:
        if seconds >= period_seconds:
            period_value, seconds = divmod(seconds, period_seconds)
            if period_value == 1:
                strings.append("%s %s" % (period_value, period_name))
            else:
                strings.append("%s %ss" % (period_value, period_name))

    return ", ".join(strings)


# Verifies whether or not a domain has a nameserver
def haz_name_server(hostname):
    # prepare dns-python query
    request = dns.message.make_query(hostname, dns.rdatatype.NS)
    request.flags |= dns.flags.AD
    ADDITIONAL_RDCLASS = 65535
    request.find_rrset \
        (request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)

    response = resolution_attempt(request, name_server_ip, max_timeout)
    if response.answer:
        for index, record in enumerate(response.answer):
            if 'NS' in str(record).split():
                return 0
            else:
                return 1


# Generic function makes dnspython request with a timeout param and retries - assumes properly formed query was passed
@riprova.retry(backoff=riprova.ConstantBackoff(interval=cfg.riprova_retry_interval, retries=cfg.riprova_max_retries))
def resolution_attempt(request, name_server_ip, max_timeout):
    try:
        response = dns.query.udp(request, name_server_ip, timeout=max_timeout)
        return response
    except:
        return 'error in resolution attempt', 1


def run_in_process_pool(size, function, input_list, description, unit):
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
            pass


# write a list to file
def write_list(list_to_write, filename):
    home = cfg.home_path
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, dialect='excel')
        writer.writerows(list_to_write)
        csvfile.flush()
