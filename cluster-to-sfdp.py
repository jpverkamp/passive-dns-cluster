#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from collections import defaultdict as ddict

domain_to_as = ddict(set)
as_to_domain = ddict(set)

current_domain = None
current_as = None

# Read DOMAIN to ASN chunk
for line in sys.stdin:
    # Continue to next chunk
    if 'ASN TO DOMAIN' in line:
        break
 
    # Skip comments and empty lines
    if line.startswith('#') or not line.strip():
        continue

    # Lines with 4 spaces are IP addresses and should be ignored
    if line.startswith('    '):
        continue

    # Lines with 2 spaces are ASNs and should be added to the current domain
    elif line.startswith('  '):
        current_as = line.strip()
        domain_to_as[current_domain].add(current_as)

    # Otherwise, we have no spaces and thus a domain, store it
    else:
        current_domain = line.strip()
   
# Reset domain and AS
current_domain = None
current_as = None

# Read ASN to domain chunk
for line in sys.stdin:

    # Skip comments and empty lines
    if line.startswith('#') or not line.strip():
        continue

    # Lines with 2 spaces are domains and should be added to the current AS
    if line.startswith('  '):
        current_domain = line.strip()
        as_to_domain[current_as].add(current_domain)

    # Otherwise, we have no spaces and thus a domain, store it
    else:
        current_as = line.strip()
    
# Print out the results as a digraph
print('digraph G_component_0 {')

# Add nodes
for domain in domain_to_as:
    print('\t"{domain}" [label="{domain}", shape=box, style=filled, color=blue];'.format(domain = domain))
for asn in as_to_domain:
    print('\t"{asn}" [label="{asn}", shape=box, style=filled, color=green];'.format(asn = asn))

# Add edges
for domain in domain_to_as:
    for asn in domain_to_as[domain]:
        print('\t"{domain}" -> "{asn}" [label=" ", color=black, arrowhead=dot];'.format(domain = domain, asn = asn))

# Close the graph 
print('}')
 
