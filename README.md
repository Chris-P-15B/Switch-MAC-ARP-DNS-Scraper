# Switch-MAC-ARP-DNS-Scraper
Copyright (c) 2023 - 2024, Chris Perkins.

An attempt to answer the question "what's connected to what?". Connects to switches in parallel, retrieves interface status & details (MAC address, IP address & hostname) of connected hosts. Then tabulates this data by MAC address & outputs to a CSV file.
Supports Aruba CX, Cisco IOS, IOS XE + NX-OS, Arista EOS & Juniper JunOS.

Caveats:
1) Currently IPv4 only for ARP entries & thus DNS lookups.

Version History:
* v1.0 - Initial public release.

# Pre-Requisites
* Python 3.7+
* NetMiko 4.1+

# Usage
Command line parameters:

* username - username to login with
* password - base64 encoded password
* filename - name of CSV file to output results into
* target device list - a space delimited list of devices to connect to

For example:

_switch-MAC-ARP-DNS-scraper.py someuser QVBhc3N3b3JkIQ== output.csv device1 device2 device3_
