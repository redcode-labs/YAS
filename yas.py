#!/usr/bin/python3.7
# [x] Add reverse DNS lookup 
# [x] Add relation tree on summary
# [x] Divide summary into separate functions
# [x] Add summary of types of packets captured
# [x] Add EAPOL analysis
# [] Add different types of .pcap output (?)
# [] Add conversation listing and division
# [] Add pattern matching
# [] Add conversation duration info (?)
# [x] Add summary output file
# [] Add quiet output
# [x] Add info about .pcap dump size <<----
# [] Add information about most common packet type in conversation
# [] Add possibility to format packet processor
# [x] Add errors to all summary tables
# [] Add hash cracking functionality
# [] Make host formatter omnipresent, but optional
# [x] Detect DC in host formatter (?)
# [x] Save found hosts to a file
# [] Add network graph generation

import argparse
from collections import Counter
from huepy import *
from scapy.all import *
import importlib
import subprocess
import netifaces
import time
import os
from dns import reversename, resolver
from terminaltables import SingleTable
import ipaddress

conf.verb = 0
packet_counts = Counter()
s = bold(cyan("#"))

def host_formatter(host, pkts):
    gateway_ip = netifaces.gateways()["default"][2][0]
    if host == gateway_ip:
        return f"{host} ({bold(cyan('G'))})" #Gateway
    for pkt in pkts:
        if (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if (sport == 389 and host == src):
                return f"{src} ({blue('DC')})" #Domain controller
            elif (dport == 389 and host == dst):
                return f"{dst} ({blue('DC')})" #Domain controller
    return host

def sizeof_fmt(num, suffix='B'): #Convert bytes to human-readable form
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def extract_ip_addresses(pkts): #Returns unique list of conversation members from PacketList() object (as a list of unique ip addresses)
    addresses = []
    for pkt in pkts:
        if pkt.haslayer(IP):
            addresses.append(pkt[IP].src)
            addresses.append(pkt[IP].dst)
    return set(addresses)

def parse_timeout_entry(entry): #Converts given interval to seconds
    num = int(entry[:-1])
    period = entry[-1]
    if period == "s":
        seconds = num
    elif period == "m":
        seconds = num * 60
    elif period == "h":
        seconds = num * 3600
    return seconds

def print_info(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"{red('[x]')} {msg}")

def print_good(msg):
    print(f"{green('[+]')} {msg}")

def sniffer_start_callback(): #This function is executed when the sniffer is launched
    print_info(f"Sniffer started ({time.strftime('%X')})")

def summary_packet_count(pkts, res):
    table_data = [["TYPE", "COUNT"]]
    packet_count_list = str(pkts).replace("<Sniffed:", "").replace(">", "").split(" ")[1:]
    for entry in packet_count_list:
        layer = entry.split(":")[0]
        count = entry.split(":")[1]
        table_data.append([layer, count])
    print(f"{s} Packet count {s}")
    if len(pkts) == 0:
        table = SingleTable([[red("No packets captured")]])
    else:
        table = SingleTable(table_data)
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"* Packet count *\n{table.table}")
    print("")

def summary_rdns_lookup(pkts, res):
    """table_data = [["IPv4", "IPv6", "HOSTNAME", "MAIL EXCHANGE", "CANONICAL NAME", "TXT RECORD"]]
    resolver.default_resolver = resolver.Resolver()
    resolver.default_resolver.nameservers = res.RDNS_LOOKUP.split(",")
    query_types = ["A", "AAAA", "PTR", "NS", "MX", "CNAME", "TXT"]
    addresses = extract_ip_addresses(pkts)
    for addr in addresses:
        for q in query_types:
            if not ipaddress.ip_address(addr).is_private:
                answer = resolver.query(reversename.from_address(addr), "PTR", raise_on_no_answer=False)
                if answer.rrset is not None:
                    print(answer.rrset)"""
    addresses = extract_ip_addresses(pkts)
    table_data = [["IP", "NAME"]]
    for addr in addresses:
        try:
            hostname = socket.gethostbyaddr(addr)[0]
        except socket.herror:
            hostname = red("UNKNOWN")
        table_data.append([addr, hostname])
    print(f"{s} rDNS lookup {s}")
    if len(addresses) == 0:
        table = SingleTable([[red("No packets with IP layer")]])
    else:
        table = SingleTable(table_data)
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")
   
def summary_trace(pkts, res): 
    table_data = [["HOST 1", "HOST 2", "COUNT"]]
    for key, count in packet_counts.items():
        table_data.append([host_formatter(key[0], pkts), host_formatter(key[1], pkts), count])
    if table_data == 1:
        table = SingleTable([[red("No packets captured")]])
    else:
        table = SingleTable(table_data)
    print(f"{s} Packet trace {s}")
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def summary_arp_mon(pkts, res):
    table_data = [[]]
    def arp_mon_display(pkt):
        if pkt[ARP].op == 1: 
            return f"{green('>')} Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
        if pkt[ARP].op == 2: 
            return f"{red('<')} Response: {pkt[ARP].hwsrc} has address {pkt[ARP].hwdst}"
    for pkt in pkts:
        if pkt.haslayer(ARP):
            table_data.append([arp_mon_display(pkt)])
    print(f"{s} ARP monitor {s}")
    #if any(pkt.haslayer(ARP) for pkt in pkts):
    if len(table_data) == 0:
        table = SingleTable(table_data[1:])
    else:
        table = SingleTable([[red("No packets with ARP layer")]])
    table.inner_heading_row_border = False
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def summary_eapol(pkts, res):
    #table_data = [["BSSID", "AUTH TYPE", "AUTH ID", "USER ID", "MD5"]]
    table_data = [[]]
    network_names = defaultdict(list)
    usernames = list()
    eapol_packets_count = 0
    for pkt in pkts:
        if (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8):
            pass        
        if pkt.haslayer(EAP):
            eapol_packets_count += 1
            if (pkt[EAP].type == 1 and pkt[EAP].code == 2):
                usr_id = pkt[EAP].id
                usr = pkt[EAP].identity
                table_data.append([f"{green('[+]')} User found: {usr}"])
            elif (pkt[EAP].type == 4 and pkt[EAP].code == 1): #EAP-MD5
                md5_challenge = pkt[EAP].load[1:17]
                table_data.append([f"{green('[+]')} EAP-MD5 : {green('request')} : {md5_challenge.encode('hex')}"])
            elif (pkt[EAP].type == 4 and pkt[EAP].code == 2):
                md5_response = pkt[EAP].load[1:17]
                table_data.append([f"{green('[+]')} EAP-MD5 : {red('response')} : {md5_challenge.encode('hex')}"])
    # TODO: Finish table_data generation
    if len(table_data) == 1 :
        table=SingleTable([[red("Nothing found")]])
    elif eapol_packets_count == 0 :
        table = SingleTable([[red("No EAP packets found")]])
    else:
        table = SingleTable(table_data[1:])
    table.inner_heading_row_border = False
    print(f"{s} EAPOL analysis {s}")
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def summary_bssids(pkts, res):
    table_data = [["SSID", "BSSID", "CHANNEL", "DBM", "ENCRYPTED", "ENCRYPTION TYPE"]]
    dot11beacon_packets_count = 0
    for pkt in pkts:
        if pkt.haslayer(Dot11Beacon):
            dot11beacon_packets_count += 1
            stats = packet[Dot11Beacon].network_stats()
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            enc = red("x")
            ssid = p[Dot11Elt].info.decode()
            bssid = p[Dot11].addr3    
            try:
                channel = int(ord(p[Dot11Elt:3].info))
            except:
                channel = stats.get("channel")
            capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            if re.search("privacy", capability): 
                enc = green("+")
            enc_type = stats.get("crypto")
            table_data.append([ssid, bssid, channel, dbm_signal, enc, enc_type])
    print(f"{s} AP discovery {s}")
    if len(pkts) == 0:
        table = SingleTable([[red("No packets captured")]])
    elif dot11beacon_packets_count == 0:
        table = SingleTable([[red("No Dot11Beacon packets found")]])
    else:
        table = SingleTable(table_data)
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def summary_host_write(pkts, res):
    found_hosts = []
    for pkt in pkts:
        if pkt.haslayer(IP):
            found_hosts.append(pkt[IP].src)
            found_hosts.append(pkt[IP].dst) 
    found_hosts = set(found_hosts) 
    for h in found_hosts:
        table_data.append(host_formatter(h, pkts))
    print(f"{s} Hosts {s}")
    #if any(pkt.haslayer(ARP) for pkt in pkts):
    if len(table_data) == 0:
        table = SingleTable(table_data[1:])
    else:
        table=SingleTable([[red("No hosts found")]])
    table.inner_heading_row_border = False
    print(table.table)
    with open(res.HOST_WRITE, "w+") as host_write_file:
        host_write_file.write("\n".join(found_hosts))
        host_write_file.close()
        print_info(f"Saved addresses of {len(found_hosts)} found hosts in {res.HOST_WRITE}")
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def summary_pattern(pkts, res):
    for pkt in pkts:
        hits = re.findall(str(pkt[Raw].load), res.PATTERN)
    print("")

def summary_http_requests(pkts, res):
    table_data = [["HOST", "URL", "METHOD"]]
    for pkt in pkts:
        if pkt.haslayer(HTTPRequest):
            url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
            method = pkt[HTTPRequest].Method.decode()
            src = pkt[IP].src
            table_data.append([src, blue(url), method])
    print(f"{s} HTTP requests {s}")
    if len(table_data) == 0:
        table = SingleTable(table_data)
    else:
        table = SingleTable([[red("No packets with HTTP layer")]])
    table.inner_heading_row_border = False
    print(table.table)
    if res.OUTPUT:
        with open(res.OUTPUT, "a") as out_file:
            out_file.write(f"\n{table.table}\n")
    print("")

def print_summary(pkts, res):
    print("")
    print_info(f"Sniffer stopped ({time.strftime('%X')})")
    print_info(f"Captured {green(len(pkts))} packets")
    if res.OUTPUT:
        print_info(f"Saved summary ouptut to {res.OUTPUT}")
    print("")
    if res.PACKET_COUNT or res.SUMMARY_FULL:
        summary_packet_count(pkts, res)
    if res.RDNS_LOOKUP or res.SUMMARY_FULL:
        summary_rdns_lookup(pkts, res)
    if res.TRACE or res.SUMMARY_FULL:
        summary_trace(pkts, res)
    if res.ARP_MON or res.SUMMARY_FULL:
        summary_arp_mon(pkts, res)    
    if res.EAPOL or res.SUMMARY_FULL:
        summary_eapol(pkts, res) 
    if res.BSSID or res.SUMMARY_FULL:
        summary_bssids(pkts, res)  
    if res.PATTERN or res.SUMMARY_FULL:
        summary_pattern(pkts, res)
    if res.HOST_WRITE or res.SUMMARY_FULL:
        summary_host_write(pkts, res)
    if res.HTTP or res.SUMMARY_FULL:
        summary_http_requests(pkts, res)

def packet_processor(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    else:
        src = pkt.src
        dst = pkt.dst
    key = tuple(sorted([src, dst]))
    packet_counts.update([key])
    pkt_no = sum(packet_counts.values())
    print(f"#{pkt_no} {pkt.summary()}")

def packet_processor_quiet(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    else:
        src = pkt.src
        dst = pkt.dst
    key = tuple(sorted([src, dst]))
    packet_counts.update([key])
    pkt_no = sum(packet_counts.values())
    
def arguments():
    parser = argparse.ArgumentParser(prog="yas", add_help=False) 
    #replay_args = parser.add_argument_group("replay arguments")
    capture_args = parser.add_argument_group("capture arguments")
    summary_args = parser.add_argument_group("summary arguments")
    output_args = parser.add_argument_group("output arguments")
    miscelanous_args = parser.add_argument_group("miscelanous arguments")

    capture_args.add_argument("-i", "--interface", dest="IFACE", action="store", default=netifaces.interfaces()[0], 
                         metavar="<iface>", choices=netifaces.interfaces(), help="Interface to sniff on")
    capture_args.add_argument("-r", "--read", dest="READ", action="store", metavar="<pcap>", help="Read packets from .pcap file instead of sniffing")
    capture_args.add_argument("-t", "--timeout", dest="TIMEOUT", action="store", metavar="<n[s|m|h]>", help="Specify sniffing time (in seconds, minutes or hours)")
    capture_args.add_argument("-c", "--count", dest="COUNT", action="store", type=int, metavar="<num>", help="Maximum number of packets to capture")
    capture_args.add_argument("-m", "--monitor", dest="MONITOR", action="store_true", help="Capture in monitor mode")
    capture_args.add_argument("-a", "--all", dest="ALL", action="store_true", help="Sniff on all interfaces at once")
    capture_args.add_argument("-sf", "--stop-filter", dest="STOP_FILTER", metavar="<lambda>", action="store", help="Specify a capture stop filter (must be Python's lambda function)")
    capture_args.add_argument("FILTER", nargs="*", help="Capture filter")     

    summary_args.add_argument("-T", "--trace", dest="TRACE", action="store_true", help="Show packets trace")
    summary_args.add_argument("-C", "--packet-count", dest="PACKET_COUNT", action="store_true", help="Show packet count")
    summary_args.add_argument("-R", "--reverse-lookup",dest="RDNS_LOOKUP", 
                                action="store_true", help="Perform reverse DNS lookup for each host")
    summary_args.add_argument("-W", "--write-hosts", nargs="?", dest="HOST_WRITE", const="found_hosts", 
                                action="store", metavar="<out_file>", help="Write found hosts to a file") 
    summary_args.add_argument("-A", "--arp-mon", dest="ARP_MON", action="store_true", help="Show ARP responses and requests")
    summary_args.add_argument("-H", "--http-requests", dest="HTTP", action="store_true", help="Show HTTP requests")
    summary_args.add_argument("-E", "--eapol", dest="EAPOL", action="store_true", help="Extract sensitive EAPOL data")
    summary_args.add_argument("-B", "--bssid", dest="BSSID", action="store_true", help="Show local access points")
    summary_args.add_argument("-P", "--pattern", dest="PATTERN", action="store", metavar="<regex>", help="Search for a regex pattern")
    summary_args.add_argument("-F", "--full", dest="SUMMARY_FULL", action="store_true", help="Show full summary")
    summary_args.add_argument("--out", dest="OUTPUT", action="store", metavar="<output_file>", help="Save the summary to a file")

    output_args.add_argument("-w", "--write", dest="WRITE", action="store", metavar="<pcap>", help="Write packets to a .pcap file")
    output_args.add_argument("--append", dest="APPEND", action="store_true", help="Append packets to a .pcap file instead of overwriting it")
    miscelanous_args.add_argument("-cl", "--clear", dest="CLEAR", action="store_true", help="Clear the screen before printing summary")
    miscelanous_args.add_argument("-q", "--quiet", dest="QUIET", action="store_true", help="Do not print basic information about captured packets")

    miscelanous_args.add_argument("-h", "--help", action="help", help="Show this help message")
    #miscelanous_args.add_argument("-l", "--list", action="store_true", help="List available output fields")
    miscelanous_args.add_argument("--async", dest="ASYNC", action="store_true", help="Start sniffer in a non-blocking mode")

    return parser.parse_args()

def main():
    global res
    res = arguments()
    if res.ALL:
        res.IFACE = netifaces.interfaces() #Pass list of all interfaces
    if res.TIMEOUT:
        res.TIMEOUT = parse_timeout_entry(res.TIMEOUT)
    res.FILTER = ' '.join(res.FILTER)
    if res.COUNT == None:
        res.COUNT = 10**10
    #Additional options setup----------------
    sniff_func="sniff"
    if res.ASYNC:
        sniff_func = "AsyncSniffer"
    if res.QUIET:
        pkt_func = packet_processor_quiet
    else:
        pkt_func = packet_processor
    #Sniffer starts here-------------------
    packets = eval(f"""{sniff_func}(iface=res.IFACE, count=res.COUNT, timeout=res.TIMEOUT, 
            offline=res.READ, filter=res.FILTER, stop_filter=res.STOP_FILTER, monitor=res.MONITOR,
            started_callback=sniffer_start_callback, prn=pkt_func)""")
    if res.CLEAR:
        os.system("cls||clear")
    print_summary(packets, res)
    if res.WRITE:
        file_size = 0
        wrpcap(res.WRITE, packets, append=res.APPEND)
        for pkt in packets: 
            file_size += len(pkt)
        print_info(f"Wrote {len(packets)} packets to {res.WRITE} ({sizeof_fmt(file_size)})")

if __name__ == "__main__": 
    main()
