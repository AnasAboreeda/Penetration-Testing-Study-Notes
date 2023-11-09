# SMB Enumeration (Server Message Block)

## Scanning for the NetBIOS Service

```ShellSession
root@kali:~# nmap -v -p 139,445 192.168.1.12 -oG /tmp/smp.txt
```

## Scanning NetBIOS using nbtscan

```ShellSession
root@kali:~# nbtscan -r 192.168.1.12
```

## Null Session Enumeration

```ShellSession
root@kali:~# enum4linux -a 192.168.1.12
```

## Nmap SMB NSE Scripts

```ShellSession
root@kali:~# ls -la /usr/share/nmap/scripts/smb*
root@kali:~# nmap -v -p 139,445 192.168.1.12 --script smb-os-discovery.nse
```

## SMBCLIENT

```ShellSession
root@kali:~#    smbclient -L=192.168.1.12
```

## Null Sessions

```ShellSession
root@kali:~#    smbclient \\\\192.168.1.12 \\public
Enter root's password:
Anonymous login successful
```

## SMB OS Discovery

```ShellSession
nmap $ip --script smb-os-discovery.ns
```

## Nmap port scan

```ShellSession
nmap -v -p 139,445 -oG smb.txt $ip-254
Netbios Information Scanning
nbtscan -r $ip/24
```

## Nmap find exposed Netbios servers

```ShellSession
nmap -sU --script nbstat.nse -p 137 $ip
```

## Nmap all SMB scripts scan

```ShellSession
nmap -sV -Pn -vv -p 445 --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip
```

Nmap all SMB scripts authenticated scan
nmap -sV -Pn -vv -p 445    --script-args smbuser=,smbpass= --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip

SMB Enumeration Tools
nmblookup -A $ip

smbclient //MOUNT/share -I $ip -N

rpcclient -U "" $ip

enum4linux $ip

enum4linux -a $ip

SMB Finger Printing
smbclient -L //$ip

Nmap Scan for Open SMB Shares
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.10.0/24

Nmap scans for vulnerable SMB Servers
nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $ip

Nmap List all SMB scripts installed
ls -l /usr/share/nmap/scripts/smb*

Enumerate SMB Users
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 $ip-14
      OR
  python /usr/share/doc/python-impacket-doc/examples /samrdump.py $ip

RID Cycling - Null Sessions
ridenum.py $ip 500 50000 dict.txt
Manual Null Session Testing

  Windows:
net use \\$ip\IPC$ "" /u:"
Linux:
smbclient -L //$ip

## SMB Enumeration Techniques using Windows Tools:


1. NetBIOS Enumerator [nbtenum](http://nbtenum.sourceforge.net/)

```ShellSession
[+] NBNS Spoof / Capture

[>] NBNS Spoof
msf > use auxiliary/spoof/nbns/nbns_response
msf auxiliary(nbns_response) > show options
msf auxiliary(nbns_response) > set INTERFACE eth0
msf auxiliary(nbns_response) > set SPOOFIP 10.10.10.10
msf auxiliary(nbns_response) > run

[>] SMB Capture

msf > use auxiliary/server/capture/smb
msf auxiliary(smb) > set JOHNPWFILE /tmp/john_smb
msf auxiliary(smb) > run

[>] HTTP NTML Capture

msf auxiliary(smb) > use auxiliary/server/capture/http_ntlm
msf auxiliary(smb) > set JOHNPWFILE /tmp/john_http
msf auxiliary(smb) > set SRVPORT 80
msf auxiliary(smb) > set URIPATH /
msf auxiliary(smb) > run
```

### SMB Enumeration

```Bash

SMB1   – Windows 2000, XP and Windows 2003.
SMB2   – Windows Vista SP1 and Windows 2008
SMB2.1 – Windows 7 and Windows 2008 R2
SMB3   – Windows 8 and Windows 2012.

```

#### Scanning for the NetBIOS Service

- The SMB NetBIOS32 service listens on TCP ports 139 and 445, as well as several UDP ports.

  ```Bash
  > nmap -v -p 139,445 -oG smb.txt 192.168.11.200-254
  ```

- There are other, more specialized, tools for specifically identifying NetBIOS information

  ```Bash
  > nbtscan -r 192.168.11.0/24
  ```

#### Null Session Enumeration

- A null session refers to an unauthenticated NetBIOS session between two computers. This feature exists to allow unauthenticated machines to obtain browse lists from other Microsoft servers.

- A null session also allows unauthenticated hackers to obtain large amounts of information about the machine, such as password policies, usernames, group names, machine names, user and host SIDs.

- This Microsoft feature existed in SMB1 by default and was later restricted in subsequent versions of SMB.

```Bash

> enum4linux -a 192.168.11.227

```

#### Nmap SMB NSE Scripts

```Bash

# These scripts can be found in the /usr/share/nmap/scripts directory
> ls -l /usr/share/nmap/scripts/smb-
# We can see that several interesting Nmap SMB NSE scripts exist,, such as OS discovery
# and enumeration of various pieces of information from the protocol
> nmap -v -p 139, 445 --script=smb-os-discovery 192.168.11.227
# To check for known SMB protocol vulnerabilities,
# you can invoke the nmap smb-check-vulns script
> nmap -v -p 139,445 --script=smb-check-vulns --script-args=unsafe=1 192.168.11.201

```


## Fix:
http://www.leonteale.co.uk/netbios-nbns-spoofing/

## Solution
The solution to this is to disable Netbios from broadcasting. The setting for this is in, what i hope, a very familiar place thaet you might not have really paid attention too before.

netbios

Netbios, according to Microsoft, is no longer needed as of Windows 2000.

However, there are a few side effects.

One of the unexpected consequences of disabling Netbios completely on your network is how this affects trusts between forests. Windows 2000 let you create an external (non-transitive) trust between a domain in one forest and a domain in a different forest so users in one forest could access resources in the trusting domain of the other forest. Windows Server 2003 takes this a step further by allowing you to create a new type of two-way transitive trusts called forest trusts that allow users in any domain of one forest access resources in any domain of the other forest. Amazingly, NetBIOS is actually still used in the trust creation process, even though Microsoft has officially “deprecated” NetBIOS in versions of Windows from 2000 on. So if you disable Netbios on your domain controllers, you won’t be able to establish a forest trust between two Windows Server 2003 forests.
But Windows 2003 is pretty old, since as of writing we are generally on Windows 2012 now. So if you would like to disable Netbios on your servers yet will be effected by the side effect for Forest trusts then ideally you should upgrade and keep up with the times anyway. alternatively, you can get away with, at the very least, disabling Netbios on your workstations.
See below for step by step instructions on disabling Netbios on workstations:

Windows XP, Windows Server 2003, and Windows 2000
On the desktop, right-click My Network Places, and then click Properties.
Right-click Local Area Connection, and then click Properties
In the Components checked are used by this connection list, double-click Internet Protocol (TCP/IP), clickAdvanced, and then click the WINS tab.Note In Windows XP and in Windows Server 2003, you must double-click Internet Protocol (TCP/IP) in the This connection uses the following items list.
Click Use NetBIOS setting from the DHCP server, and then click OK three times.

For Windows Vista
On the desktop, right-click Network, and then click Properties.
Under Tasks, click Manage network connections.
Right-click Local Area Connection, and then click Properties
In the This connection uses the following items list, double-click Internet Protocol Version 4 (TCP/IPv4), clickAdvanced, and then click the WINS tab.
Click Use NetBIOS setting from the DHCP server, and then click OK three times.

For Windows 7
Click Start, and then click Control Panel.
Under Network and Internet, click View network status and tasks.
Click Change adapter settings.
Right-click Local Area Connection, and then click Properties.
In the This connection uses the following items list, double-click Internet Protocol Version 4 (TCP/IPv4), clickAdvanced, and then click the WINS tab.
Click Use NetBIOS setting from the DHCP server, and then click OK three times.
