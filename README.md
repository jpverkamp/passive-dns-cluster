Scan JSON formatted ISC-SIE passive DNS records and create domain->asn and asn->domain maps.

    Usage:
    ./passive-dns-cluster.py files*

		files can be:
		  -    for standard in
      *.gz for a gzipped file
      *    for plain text

Output will be two hierarchical maps:

    domain_to_asn : domain -> asn -> ip -> count
    asn_to_domain : asn -> set(domain)

Requires the following git submodules:

- [alexa](git://github.com/jpverkamp/alexa.git)
- [etld](git://github.com/jpverkamp/etld.git)
- [ip2asn](git://github.com/jpverkamp/ip2asn.git)
