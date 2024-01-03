# Nmap-summary

# Nmap Summary (ESP)

```
nmap -sV -sC -O -n -p- -oA nmapscan $IP
```

## Parameters

### IPs to Scan

- **`<ip>,<net/mask>`:** Indicate the ips directly
- **`iL <ips_file>`:** list_IPs
- **`iR <number>`**: Number of random Ips, you can exclude possible Ips with `-exclude <Ips>` or `-excludefile <file>`.

### Equipment Discovery

By default Nmap launches a discovery phase consisting of: `-PA80 -PS443 -PE -PP`

- **`sL`**: It is not invasive, it lists the targets making **DNS** requests to resolve names. It is useful to know if for example <www.prueba.es/24> all Ips are our targets.
- **`Pn`**: **No ping**. This is useful if you know that all of them are active (if not, you could lose a lot of time, but this option also produces false negatives saying that they are not active), it prevents the discovery phase.
- **`sn`**: **No port scan**. After completing the reconnaissance phase, it does not scan ports. It is relatively stealthy, and allows a small network scan. With privileges it sends an ACK (-PA) to 80, a SYN(-PS) to 443 and an echo request and a Timestamp request, without privileges it always completes connections. If the target is the network, it only uses ARP(-PR). If used with another option, only the packets of the other option are dropped.
- **`PR`**: **Ping ARP**. It is used by default when analyzing computers in our network, it is faster than using pings. If you do not want to use ARP packets use `-send-ip`.
- **`PS <ports>`**: It sends SYN packets to which if it answers SYN/ACK it is open (to which it answers with RST so as not to end the connection), if it answers RST it is closed and if it does not answer it is unreachable. In case of not having privileges, a total connection is automatically used. If no ports are given, it throws it to 80.
- **`PA <ports>`**: Like the previous one but with ACK, combining both of them gives better results.
- **`PU <ports>`**: The objective is the opposite, they are sent to ports that are expected to be closed. Some firewalls only check TCP connections. If it is closed it is answered with port unreachable, if it is answered with another icmp or not answered it is left as destination unreachable.
- **`PE, -PP, -PM`**: ICMP PINGS: echo replay, timestamp and addresmask. They are launched to find out if the target is active.
- **`PY<ports>`**: Sends SCTP INIT probes to 80 by default, INIT-ACK(open) or ABORT(closed) or nothing or ICMP unreachable(inactive) can be replied.
- **`PO <protocols>`**: A protocol is indicated in the headers, by default 1(ICMP), 2(IGMP) and 4(Encap IP). For ICMP, IGMP, TCP (6) and UDP (17) protocols the protocol headers are sent, for the rest only the IP header is sent. The purpose of this is that due to the malformation of the headers, Protocol unreachable or responses of the same protocol are answered to know if it is up.
- **`n`**: No DNS
- **`R`**: DNS always

### Port Scanning Techniques

- **`sS`**: Does not complete the connection so it leaves no trace, very good if it can be used.(privileges) It is the one used by default.
- **`sT`**: Completes the connection, so it does leave a trace, but it can be used for sure. By default without privileges.
- **`sU`**: Slower, for UDP. Mostly: DNS(53), SNMP(161,162), DHCP(67 and 68), (-sU53,161,162,67,68): open(reply), closed(port unreachable), filtered (another ICMP), open/filtered (nothing). In case of open/filtered, -sV sends numerous requests to detect any of the versions that nmap supports and can detect the true state. It increases a lot the time.
- **`sY`**: SCTP protocol fails to establish the connection, so there are no logs, works like -PY
- **`sN,-sX,-sF`:** Null, Fin, Xmas, they can penetrate some firewalls and extract information. They are based on the fact that standard compliant machines should respond with RST all requests that do not have SYN, RST or ACK lags raised: open/filtered(nothing), closed(RST), filtered (ICMP unreachable). Unreliable on WIndows, CIsco, BSDI and OS/400. On unix yes.
- **`sM`**: Maimon scan: Sends FIN and ACK flags, used for BSD, currently will return all as closed.
- **`sA, sW`**: ACK and Window, is used to detect firewalls, to know if the ports are filtered or not. The -sW does distinguish between open/closed since the open ones respond with a different window value: open (RST with window other than 0), closed (RST window = 0), filtered (ICMP unreachable or nothing). Not all computers work this way, so if it is all closed, it is not working, if it is a few open, it is working fine, and if it is many open and few closed, it is working the other way around.
- **`sI`:** Idle scan. For the cases in which there is an active firewall but we know that it does not filter to a certain Ip (or when we simply want anonymity) we can use the zombie scanner (it works for all the ports), to look for possible zombies we can use the scrpit ipidseq or the exploit auxiliary/scanner/ip/ipidseq. This scanner is based on the IPID number of the IP packets.
- **`-badsum`:** It sends the sum wrong, the computers would discard the packets, but the firewalls could answer something, it is used to detect firewalls.
- **`sZ`:** "Weird" SCTP scanner, when sending probes with cookie echo fragments they should be dropped if open or responded with ABORT if closed. It can pass through firewalls that init does not pass through, the bad thing is that it does not distinguish between filtered and open.
- **`sO`:** Protocol Ip scan. Sends bad and empty headers in which sometimes not even the protocol can be distinguished. If ICMP unreachable protocol arrives it is closed, if unreachable port arrives it is open, if another error arrives, filtered, if nothing arrives, open|filtered.
- **`b <server>`:** FTPhost–> It is used to scan a host from another one, this is done by connecting the ftp of another machine and asking it to send files to the ports that you want to scan from another machine, according to the answers we will know if they are open or not. [<user>:<password>@]<server>[:<port>] Almost all ftps servers no longer let you do this and therefore it is of little practical use.

### Translation and Summary of Nmap Analysis Focus

### Port Specification

- **p:** Select ports to scan. Use **p-** or **p all** for all 65335 ports. Nmap defaults to the top 1000 ports. Use **F** for a fast scan of the top 100 ports. **–top-ports <number>** scans the specified number of popular ports. **r** avoids random order. Specify ranges or individual ports.

### Version Scanning

- **sV:** Adjust scan intensity from 0 to 9 (default 7).
- **–version-intensity <number>**: Lower values use only the most likely probes, reducing UDP scan time.

### OS Detection

- **O:** OS detection.
- **–osscan-limit:** Requires at least one open and one closed port to attempt OS prediction.
- **–osscan-guess:** Tries harder when OS detection isn't certain.

### Scripts

- **–script <filename>|<category>|<directory>|<expression>**: Use default scripts with -sC or–script=default. Categories include auth, broadcast, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln.
- **–script-args** and **–script-args-file**: Customize script arguments.
- **–script-trace**: Shows script execution details.
- **–script-updatedb**: Updates the script database.

### Time Control

- **–host-timeout**: Set timeout for host scanning.
- **–min-hostgroup/–max-hostgroup**: Adjust parallel scan group sizes.
- **–min-parallelism/–max-parallelism**: Control parallelism (automatic adjustment is recommended).
- **–min-rtt-timeout/–max-rtt-timeout/–initial-rtt-timeout**: Set round-trip time timeouts.
- **–max-retries**: Set the maximum number of retries.
- **–scan-delay/–max-scan-delay**: Set delays between probes.
- **–min-rate/–max-rate**: Control packet rate.
- **–defeat-rst-ratelimit**: Speed up scans for open ports.
- **T0 to -T5**: Adjust scan aggressiveness.

### Firewall/IDS Evasion

- **f**: Fragment packets.
- **D**: Use decoys.
- **S IP**: Spoof source IP.
- **e <interface>**: Choose a network interface.
- **–source-port/-g**: Use specific source ports.
- **–data/–data-string/–data-length**: Send custom payload.
- **–ip-options**: Customize IP packet options.
- **–ttl**: Set the TTL value.
- **–randomize-hosts**: Randomize target order.
- **–spoof-mac**: Spoof MAC address.
- **–proxies**: Use proxies.
- **sP**: Discover hosts using ARP.

### Output Options

- **oN/-oX/-oG/-oA**: Output formats (normal, XML, grepable, all).
- **v/-d**: Verbosity and debugging levels.
- **–reason**: Show reasons for port states.
- **–stats-every**: Periodic progress updates.
- **–packet-trace**: Trace packets.
- **–open**: Show only open ports.
- **–resume**: Resume a previous scan.

### Miscellaneous

- **6**: Enable IPv6 scanning.
- **A**: Equivalent to -O -sV -sC–traceroute.
- **Run time**: Change options during scan execution.

### Vulscan

- Nmap script for vulnerability scanning using various databases.
- Download and installation instructions provided.

### Speed Up Nmap Service Scan

- Modify `totalwaitms` and `tcpwrappedms` in `/usr/share/nmap/nmap-service-probes` to speed up scans.
- Compile Nmap with customized settings for faster service scanning.
