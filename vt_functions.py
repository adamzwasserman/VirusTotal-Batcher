#  Python 3.6 modules
import re
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import json
import time

#  MIT licensed 3rd party modules
import riprova

#  import config data and grab api_key
import config as cfg

api_key = cfg.api_key


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
                r'(^https?://)([^\/]+?\.)([^\/]+/?)(.+)', re.IGNORECASE) #  (http(s)://) (hostname) (domain name) (params)
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
    print('Error exception: {}'.format(err))
    print('Next try in {}ms'.format(next_try))


#  Function to lookup Domains
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=1, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1.5),
    on_retry=on_retry)
def lookup_domains(vt_lookup_value):
    list_to_return = []
    error_to_return = []
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': vt_lookup_value, 'apikey': api_key}

    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)
        response_json = json.loads(response)

        if response_json['response_code'] is 1:
            vt_status = response_json['verbose_msg']
            vt_ip = ''
            vt_date = ''
            vt_subdomain = ''
            vt_url = ''
            vt_score = ''
            list_to_return = [(vt_lookup_value, vt_status, vt_ip, vt_date, vt_subdomain, vt_url, vt_score)]
            vt_status = ''

            try:
                if response_json['resolutions']:
                    for _ in response_json['resolutions']:
                        vt_ip = response_json['resolutions'][0]['ip_address']
                        vt_date = response_json['resolutions'][0]['last_resolved']
                        list_to_return.append(
                            (vt_lookup_value, vt_status, vt_ip, vt_date, vt_subdomain, vt_url, vt_score))
                    vt_ip = ''
                    vt_date = ''
            except KeyError:
                pass

            try:
                if response_json['subdomains']:
                    for i in response_json['subdomains']:
                        vt_subdomain = i
                        list_to_return.append(
                            (vt_lookup_value, vt_status, vt_ip, vt_date, vt_subdomain, vt_url, vt_score))
                    vt_subdomain = ''
            except KeyError:
                pass

            try:
                if response_json['detected_urls']:
                    for i in response_json['detected_urls']:
                        vt_url = i['url']
                        vt_date = i['scan_date']
                        vt_score = i['positives']
                        list_to_return.append(
                            (vt_lookup_value, vt_status, vt_ip, vt_date, vt_subdomain, vt_url, vt_score))
            except KeyError:
                pass

        else:
            vt_status = response_json['verbose_msg']
            error_to_return = [(vt_lookup_value, vt_status)]

    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        error_to_return = [(vt_lookup_value, vt_status)]

    return list_to_return, error_to_return


#  Function to lookup URLs
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=1, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1.5),
    on_retry=on_retry)
def lookup_urls(vt_lookup_value):
    list_to_return = []
    error_to_return = []
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    if vt_lookup_value[-1::] is '/':
        parameters = {'apikey': api_key, 'resource': vt_lookup_value[:-1:]}
    else:
        parameters = {'apikey': api_key, 'resource': vt_lookup_value}

    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)
        response_json = json.loads(response)

        if response_json['response_code'] is 1:
            try:
                vt_score = response_json['positives']
                vt_date = response_json['scan_date']
                vt_status = response_json['verbose_msg']
                vt_url = response_json['url']
                list_to_return = [(vt_lookup_value, vt_score, vt_date, vt_status, vt_url)]
            except KeyError:
                pass

        else:
            vt_status = response_json['verbose_msg']
            error_to_return = [(vt_lookup_value, vt_status)]

    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        error_to_return = [(vt_lookup_value, vt_status)]

    return list_to_return, error_to_return


#  Function to force-lookup URLs
@riprova.retry(
    backoff=riprova.ExponentialBackOff(interval=1, factor=0.5, max_interval=60, max_elapsed=900, multiplier=1.5),
    on_retry=on_retry)
def force_urls(vt_lookup_value):
    time.sleep(cfg.request_wait)
    list_to_return = []
    error_to_return = []
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'

    if vt_lookup_value[-1::] is '/':
        parameters = {'apikey': api_key, 'url': vt_lookup_value[:-1:]}
    else:
        parameters = {'apikey': api_key, 'url': vt_lookup_value}

    data = urllib.parse.urlencode(parameters)
    data = data.encode('UTF-8')

    response = urllib.request.Request(url, data)
    with urllib.request.urlopen(response) as response:
        the_page = response.read()
    response_json = json.loads(the_page)

    if response_json['response_code'] is 1:
        vt_status = response_json['verbose_msg']
        vt_score = ''
        vt_date = ''
        vt_url = ''

        try:
            vt_date = response_json['scan_date']
            vt_url = response_json['url']
        except KeyError:
            pass

        list_to_return = [(vt_lookup_value, vt_score, vt_date, vt_status, vt_url)]
        list_to_return.extend(lookup_urls(vt_lookup_value))

    else:
        vt_status = response_json['verbose_msg']
        error_to_return = [(vt_lookup_value, vt_status)]

    return list_to_return, error_to_return


#  Function to lookup IPs
def lookup_ips(passed_value):
    lookup_list = ipaddress.ip_network(passed_value,
                                       strict=False)  # expands CIDR into list of IPs, no effect on single IPs

    for vt_lookup_value in lookup_list:
        print('Looking up', vt_lookup_value, end='..')
        good, bad = lookup_slash_ips(vt_lookup_value)  # Call subroutine, remember it returns a tuple of lists

    return good, bad


#  Subroutine to step through "slash" IP networks
@riprova.retry(backoff=riprova.ExponentialBackOff(interval=2, factor=0.5, max_interval=60, max_elapsed=cfg.max_wait,
                                                  multiplier=1.5), on_retry=on_retry)
def lookup_slash_ips(vt_lookup_value):
    loop_list = []
    error_to_return = []
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': vt_lookup_value, 'apikey': api_key}

    try:
        print(".", end='')
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        time.sleep(cfg.request_wait)
        response_json = json.loads(response)

        if response_json['response_code'] is 1:
            vt_status = response_json['verbose_msg']
            vt_date = ''
            vt_hostname = ''
            vt_url = ''
            vt_score = ''
            loop_list = [(vt_lookup_value, vt_status, vt_date, vt_hostname, vt_url, vt_score)]
            print(vt_status)
            vt_status = ''

            try:
                if response_json['resolutions']:
                    for i in response_json['resolutions']:
                        vt_date = str(i['last_resolved'])
                        vt_hostname = str(i['hostname'])
                        loop_list.append((vt_lookup_value, vt_status, vt_date, vt_hostname, vt_url, vt_score))
            except KeyError:
                pass

            try:
                if response_json['detected_urls']:
                    for i in response_json['detected_urls']:
                        vt_date = str(i['scan_date'])
                        vt_url = str(i['url'])
                        vt_score = str(i['positives'])
                        loop_list.append((vt_lookup_value, vt_status, vt_date, vt_hostname, vt_url, vt_score))
            except KeyError:
                pass
        else:
            vt_status = response_json['verbose_msg']
            error_to_return = [(vt_lookup_value, vt_status)]

        return loop_list, error_to_return

    except urllib.error.URLError as e:
        vt_status = 'ERROR: ' + e.reason
        error_to_return = [(vt_lookup_value, vt_status)]
        return loop_list, error_to_return


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
