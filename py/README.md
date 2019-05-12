### DNS Deceiver

Python version of ARP-spoofing tool with blackjack and hook..s. Created as my uni project. 

### Installation

```bash
pip install -r requirements.txt --user
```

Make sure you are running netfilter on your machine.

### Usage

To print the help message simply type `python dnsdeceiver.py -h`

```bash
~/.../py/dnsdeceiver >>> sudo !!                                                                                                                                                 ±[●●][master]
sudo python dnsdeceiver.py -h
[sudo] password for $USERNAME: 

        ____  _  _  ___    ____  ____  ___  ____  ____  _  _  ____  ____ 
       (  _ \( \( )/ __)  (  _ \( ___)/ __)( ___)(_  _)( \/ )( ___)(  _ \
        )(_) ))  ( \__ \   )(_) ))__)( (__  )__)  _)(_  \  /  )__)  )   /
       (____/(_)\_)(___/  (____/(____)\___)(____)(____)  \/  (____)(_)\_)
                                                       by foxtrot_charlie
       
usage: dnsdeceiver.py [-h] [-f config.toml]
                      [-d [site.pl:evil_site.pl [site.pl:evil_site.pl ...]]]
                      [-a [IP [IP ...]]]

Small tool to spoof/edit DNS responses using ARP spoofing.

optional arguments:
  -h, --help            show this help message and exit
  -f config.toml, --config config.toml
                        config TOML file
  -d [site.pl:evil_site.pl [site.pl:evil_site.pl ...]], --dns [site.pl:evil_site.pl [site.pl:evil_site.pl ...]]
                        List of DNS queries (comma-separated) to be spoofed
                        (addr:spoofed pairs)
  -a [IP [IP ...]], --arp [IP [IP ...]]
                        List of IP addresses (comma-separated) to be attacked
                        via ARP spoofing (0.0.0.0 for whole network)

Handle with care!
```

Example config was provided in file called `config.toml`. All parameters are pretty self-explanatory.

```toml
[arp]
target = ["192.168.0.11"]
gateway = "192.168.0.1"
network = '192.168.0.0/24'

[dns]
    [dns.target]
    "foxtrotlabs.cc" = "192.168.0.15"
    "gynvael.coldwind.pl" = "192.168.0.15"
    "wp.pl" = "192.168.0.15"

[attack]
interface = "interface"
```

`[arp]` section is provides options to configure arp-spoofing attack. 
* target array specifies targets to be spoofed using ARP packets
* gateway sets the IP addr of the gateway
* network sets the netwrok address with the mask. This setting is handy when target list is emtpy/not provided. This script will then manually check all the hosts using self-implemented arpping utility 

`[dns]` section configures mapping to be applied when spoofing DNS responses. In `[dns.target]` targets are specified with `key = value` entries, where key is the domain to be spoofed and domain value holds the IP address to be put into DNS response. 

`[attack]` section is used to configure settings of attacker machine. The only needed value is the `interface` wich specifies which interface should be used to run the attack. 


### How it works

DNS-spoofing is a very simple attack. The attacker sniffs incoming DNS responses and spoofs the IP address of queried domain.  
To receive DNS queries sent by the victim machine, the attacker has to redirect whole traffic via his/her controlled machine. That's why DNS spoofing attacks are usually conducted over conducted ARP spoofing attack.

The ARP spoofing attack is yet another trivial computer network attack. The attacker has to put himself/herself in the middle of communication between gateway and the victim host. This can be done by poisoning ARP tables on both machines. 

It is achieved by sending fake ARP responses (not requested!) to the network. Incomming information will be used to overwrite nonstatic entry in the ARP table. In other words: the attackers tells the victiom "Hi, my name is YourRouter". And the gateway gets very similar message "Hi there, my name is Victim".   
Of course by filling corresponding fields in the ARP packet. 


Asciiart graph (coz everything with asciiart has more awesome phrack-like experience!) 
```

``` 

### Commandline interface

TBA
