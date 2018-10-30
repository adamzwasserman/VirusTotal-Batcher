# Python modules
import socket
import random
from multiprocessing import Process, Queue
import time

# 3rd party modules
import arrow
import riprova
import dns.name
import dns.message
import dns.query
import dns.flags
import dns.resolver

# Local modules
import config as cfg


# Reno version
version_info = (2,0,7)
version = '.'.join(str(c) for c in version_info)


# Global variables
starting_nameservers = [
    ('a.root-servers.net.', '198.41.0.4'),
    ('b.root-servers.net.', '199.9.14.201'),
    ('c.root-servers.net.', '192.33.4.12'),
    ('d.root-servers.net.', '199.7.91.13'),
    ('e.root-servers.net.', '192.203.230.10'),
    ('f.root-servers.net.', '192.5.5.241'),
    ('g.root-servers.net.', '192.112.36.4'),
    ('h.root-servers.net.', '198.97.190.53'),
    ('i.root-servers.net.', '192.36.148.17'),
    ('j.root-servers.net.', '192.58.128.30'),
    ('k.root-servers.net.', '193.0.14.129'),
    ('l.root-servers.net.', '199.7.83.42'),
    ('m.root-servers.net.', '202.12.27.33')]


def standalone(hostname_to_resolve):
    # a_record = resolve_hostname([random.choice(starting_nameserver)], hostname_to_resolve)

    # convert hostname to dns-python object
    hostname = dns.name.from_text(hostname_to_resolve)
    if not hostname.is_absolute():
        hostname = hostname.concatenate(dns.name.root)

    ns_ip_list = [random.choice(starting_nameservers)]

    a_record, hit = recursive_a_lookup(ns_ip_list, hostname, [])
    # domain_status = w.try_pythonwhois_with_timeout(str(hostname), 0.5)

    return hostname, a_record


def main(hostname_to_resolve):
    # a_record = resolve_hostname([random.choice(starting_nameserver)], hostname_to_resolve)

    # convert hostname to dns-python object
    hostname = dns.name.from_text(hostname_to_resolve)
    if not hostname.is_absolute():
        hostname = hostname.concatenate(dns.name.root)

    ns_ip_list = [random.choice(starting_nameservers)]

    a_record, hit = recursive_a_lookup(ns_ip_list, hostname, [])
    # domain_status = w.try_pythonwhois_with_timeout(str(hostname), 0.5)

    return a_record


def recursive_a_lookup(ns_list, hostname, nameservers_queried):
    # prepare dns-python query
    request = dns.message.make_query(hostname, dns.rdatatype.A)
    request.flags |= dns.flags.AD
    ADDITIONAL_RDCLASS = 65535
    request.find_rrset\
        (request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)

    # We are going to loop through a list of nameservers to recursively resolve from root to authoritative,
    # if it fails we we break and try next
    # lookup_result will be written to disk at the end, it's updated each time a case is met, last matched case prevails
    hit = 0
    index = 0
    for name_server, name_server_ip in ns_list:

        #check if this is the last iteration, if so set the time out longer as a last gasp attempt
        index += 1
        max_timeout = cfg.reno_max_timeout_in_seconds
        if index == len(ns_list):
            max_timeout = cfg.reno_overall_timeout

        # Which name server we are querying in this iteration (for error messages)
        resolving_ns = name_server

        # Don't re-querying previously queried NS
        if name_server in nameservers_queried:
            lookup_result = 'LOOP, {} points to itself'.format(resolving_ns)
            continue
        else:
            nameservers_queried.append(name_server)

        # Try to resolve hostname. Successful resolutions return a dnspython object so str type means the lookup failed
        response = resolution_attempt(request, name_server_ip, max_timeout)
        if type(response) is tuple:
            lookup_result = 'RETRY'
            continue

        elif not response.answer and not response.authority:
            lookup_result = 'RETRY'
            continue

        rcode = response.rcode()

        if rcode == dns.rcode.NXDOMAIN:
            hit = 1
            lookup_result = 'NXDOMAIN'

        elif rcode == dns.rcode.SERVFAIL:
            hit = 1
            lookup_result = 'SERVFAIL'

        elif rcode == dns.rcode.REFUSED:
            hit = 1
            lookup_result = 'REFUSED'

        # elif 'refused' in str(response).lower():
        #     hit = 1
        #     lookup_result = 'REFUSED'

        elif response.answer:
            for index, record in enumerate(response.answer):
                if 'CNAME' in str(record).split():
                    hit = 1
                    lookup_result = '{}'.format(str(record).split()[4])
                elif 'A' in str(record).split():
                    hit = 1
                    lookup_result = "{}".format(str(record).split()[4])

        if hit is 1:
            return lookup_result, hit

        else:
            # There was no authoritative response yet. Build a list of all next hop nameservers and recurse
            authorities_list = [str(record).split()[0] for record in response.authority[0].items if record.rdtype is 2]
            authorities_list = winnow_nameservers(authorities_list)
            if not authorities_list:
                lookup_result = 'RETRY'
            else:
                if response.additional:
                    authorities_list = [(str(line.name), line.items[0].address) for line in response.additional
                                        if str(line.name) in authorities_list and 'AAAA' not in str(line)]
                else:
                    authorities_list = [(ns_host, resolve_nameserver(ns_host)) for ns_host in authorities_list
                                        if resolve_nameserver(ns_host) is not 'nstimeout']
                    if not authorities_list:
                        lookup_result = 'noip'
                        continue
                if authorities_list:
                    lookup_result, hit = recursive_a_lookup(authorities_list, hostname, nameservers_queried)
                    if hit is 1:
                        return lookup_result, hit
                else:
                    lookup_result = 'noip'
                    continue

    try:
        if lookup_result is 'timeout':
            lookup_result = 'RETRY'
            return lookup_result, 1

        elif lookup_result is 'RETRY':
            return lookup_result, 1
        elif lookup_result is 'noip':
            lookup_result = 'RETRY'
            return lookup_result, 1

    except Exception as e:
        print('{} happened resolving {}. There were {} iterations.'.format(e, hostname, len(nameservers_queried)))

    # Handle case where there were no timeouts and no hits, write/return most recent lookup_value which contains error
    try:
        with open(cfg.reno_error_file_name, 'a') as f:
            f.write("{},{},{}\n".format(str(hostname)[:-1], lookup_result, arrow.now().format('YYYY-MM-DD HH-mm')))
        return lookup_result, 1
    except Exception as e:
        with open(cfg.reno_error_file_name, 'a') as f:
            f.write("{},{},{}\n".format(str(hostname)[:-1], e, arrow.now().format('YYYY-MM-DD HH-mm')))


@riprova.retry(backoff=riprova.ConstantBackoff(interval=cfg.riprova_retry_interval, retries=cfg.riprova_max_retries))
def resolution_attempt(request, name_server_ip, max_timeout):
    try:
        response = dns.query.udp(request, name_server_ip, timeout=max_timeout)
        return response
    except:
        return 'error in resolution attempt (r181)', 1


# Winnow lists of nameservers down to one for domains where we are sure all nameservers agree
def winnow_nameservers(list_of_nameservers):
    reliable_zone_cuts = ['root-servers.net', 'gtld-servers.net', 'nic.fr', 'nic.de', 'de.net',
                          'gtld.biz', 'nstld.com', 'gtld.travel', 'ca-servers.ca', 'dns.jp', 'cctld.us', 'dns.cn',
                          'in.afilias-nst.org', 'denic.de']
    hits = []
    for nameserver in list_of_nameservers:
        if not any(rzc in nameserver for rzc in reliable_zone_cuts):
            hits = list_of_nameservers
        elif not hits and any(rzc in nameserver for rzc in reliable_zone_cuts):
            hits.append(nameserver)
    return hits


# Get the name server ip. dnspython requires ips not names for NS param.
# using a queue because it is impossible to set timeout for socket.gethostbyname, resulting in 90 second delays

def ns_lookup(host, q):
    try:
        nsip = socket.gethostbyname(host)
        q.put(nsip)
    except:
        pass


def resolve_nameserver(ns_hostname):
    # set up queue and start the query
    q = Queue()
    p = Process(target=ns_lookup, args=(ns_hostname, q,))
    p.start()

    # try once before sleeping, to try and avoid enforced latency of time.sleep, then sleep if necessary, then try again
    if not q.empty():
        return q.get()

    counter = 0
    while q.empty() and counter < cfg.reno_ns_timeout_in_seconds:
        time.sleep(0.1)
        counter += 1

    if q.empty():
        p.terminate()
        return 'nstimeout'
    else:
        return q.get()


if __name__ == '__main__':
    print(main('21mov.epizy.com'))
