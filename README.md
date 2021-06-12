# YAS ![Platform](https://img.shields.io/badge/Platform-Linux/Windows-purple.svg?longCache=true&style=flat-square) ![Language](https://img.shields.io/badge/Python-3.7-blue.svg?longCache=true&style=flat-square)   ![License](https://img.shields.io/badge/License-MIT-red.svg?longCache=true&style=flat-square)



YAS (Yet Another Sniffer) is a Scapy-based network analyzer. It bundles some useful functionalities into a single tool, making it easy to extract different information about network traffic.

<p align="center">
<img src="screenshot.png" width="836"/>
</p>



## Features
- Read from and write to .pcap files
- Monitor ARP requests/responses
- Sniff on multiple interfaces
- Extract EAPOL data
- Save detected hosts to a file
- Perform reverse DNS lookup
- Show local access points
- Show packet trace and detailed packets count
- Highlight local Gateway and Domain Controller
- Search for regular expressions
- Monitor HTTP requests
- Sniff in asynchronous mode

## Examples of use
Read packets from a .pcap file; show information about Access Points:

`./yas.py -r file.pcap -B`

Show ARP traffic and reverse DNS lookup; sniff on all interfaces and write capture to .pcap: 

`./yas.py -a -A -R`-w file.pcap

Run sniffer for 10 minutes on selected interface, and write IP addresses of found hosts to a file:

`./yas -t 10m -W hosts_file -i wlan0`


## Help menu
<p align="center">
<img src="screenshot1.png" width="836"/>
</p>





## License
This software is under [MIT License](https://en.wikipedia.org/wiki/MIT_License)