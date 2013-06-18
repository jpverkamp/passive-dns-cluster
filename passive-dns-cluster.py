#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import alexa
import etld
import ip2asn
import gzip
import json
import os
import re
import sys
import string
import time

from collections import defaultdict as ddict

def log(msg):
    """Log messages using stderr so redirection and pipes work as expected."""

    sys.stderr.write(msg)
    sys.stderr.write('\n')
    sys.stderr.flush()

# Command line parameters
FILTER_TOP_DOMAINS = 1000  # Filter only the top this many domains
DEBUG_MODE         = True  # If debug mode is true, print occasional progress messages
DEBUG_INTERVAL     = 10000 # Print progress messages every this many records

# : domain -> asn -> ip -> count
domain_to_asn = ddict(lambda : ddict(lambda : ddict(lambda : 0)))

# : asn -> set(domain)
asn_to_domain = ddict(set)

def fix_url(url):

    """
    Fix those crazy formatted URLs.

    Convert all non-url characters to dots then remove multiple dots.
    re_url_fix and re_replace_chars are each generated once and should not be passed
    """

    return ''.join(c if c.isalnum() or c in '-~_.' else '.' for c in url).strip('.')

def scan(fin):
    """
    Read a series of passive DNS entries from a file.

    Each line should be a JSON object in the ISC-SIE format.
    Any filelike object should work.
    """

    start_time = time.time()
    line_count = 0

    for line in fin:
        line_count += 1
        if DEBUG_MODE and line_count % DEBUG_INTERVAL == 0:
            log('{} lines processed in {:.2f} seconds'.format(line_count, time.time() - start_time))

        if isinstance(line, bytes): # Fix for gzip returning bytes instead of a string
            js = json.loads(line.decode('utf-8'))
        else:
            js = json.loads(line)

        packet_type = js['type'] if 'type' in js else None
        query_type = js['qtype'] if 'qtype' in js else None

        # Process A records
        if packet_type  == 'UDP_QUERY_RESPONSE' and query_type == 1:
            # Process query (domain)
            query = js['qname']
            url = fix_url(query)
            url_parts = etld.split(url)
            if url_parts:
                domain = '.'.join(url_parts)
            else:
                continue # Invalid domain name, skip 

            # Process response (ip)            
            response = js['response_ip']
            ip = response
            if '.' in ip:
                asn = ip2asn.ip2asn(ip)
            else:
                continue # Invalid IP (likely IPv6), skip

            # Ignore anything that's no in the Alexa Top N
            if not alexa.is_top_n(domain, FILTER_TOP_DOMAINS):
                continue

            # Store any interesting information

            # : domain -> asn -> ip -> count
            domain_to_asn[domain][asn][ip] += 1

            # : asn -> set(domain)
            asn_to_domain[asn].add(domain)

if __name__ == '__main__':
    for arg in sys.argv[1:]:
        fin = None

        # Open the correct file-like object:
        #   -    for stdin
        #   *.gz for a gzipped file
        #   *    for any other file
        if arg == '-':
            fin = sys.stdin
        elif os.path.exists(arg):
            if arg.endswith('gz'):
                fin = gzip.open(arg, 'r')
            else:
                fin = open(arg, 'r')

        if fin:
            scan(fin)
            fin.close()
        else:
            print('Could not read "{}", not a valid file.'.format(arg))

    # Once all is said and done, print results            

    print('# ----- DOMAIN TO ASN ----- #\n')
    for domain in domain_to_asn:
        print('{}'.format(domain))
        for asn in domain_to_asn[domain]:
            print('  {}'.format(asn))
            for ip in domain_to_asn[domain][asn]:
                print('    {} = {}'.format(ip, domain_to_asn[domain][asn][ip]))
        print()

    print('# ----- ASN TO DOMAIN ----- #\n')
    for asn in asn_to_domain:
        print('{}'.format(asn))
        for domain in asn_to_domain[asn]:
            print('  {}'.format(domain))
        print()
