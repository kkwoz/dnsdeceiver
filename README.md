### DNS Deceiver

Python version of an ARP-spoofing tool with blackjack and hook..s. Created as my uni project. 

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

`[arp]` section provides options to configure the arp-spoofing attack. 
* target array specifies targets to be spoofed using ARP packets
* gateway sets the IP address of the gateway
* network sets the network address with the mask. This setting is handy when the target list is empty/not provided. This script will then automatically check all the hosts using self-implemented arpping utility 

`[dns]` section configures mapping to be applied when spoofing DNS responses. In `[dns.target]` targets are specified with `key = value` entries, where the key is the domain to be spoofed and the domain value holds the IP address to be put into the DNS response. 

`[attack]` section configures settings of the attacker machine. The only required value is `interface` which specifies which interface should be used to run the attack. 


### How it works

DNS-spoofing is a very simple attack. The attacker sniffs incoming DNS responses and spoofs the IP address of the queried domain.  
To receive DNS queries sent by the victim machine, the attacker has to redirect the whole traffic via their controlled machine. That is why DNS-spoofing attacks are usually conducted over ARP-spoofing attacks.

ARP-spoofing is yet another trivial computer network attack. The attacker has to put themselves in the middle of the communication between the gateway and the victim host. This can be done by poisoning ARP tables on both machines. 

It is achieved by sending fake ARP responses (not requested!) to the network. Incoming information will be used to overwrite nonstatic entries in the ARP table. In other words: the attacker tells the victim "Hi, my name is YourRouter". And the gateway gets a very similar message - "Hi there, my name is Victim".   
Of course by filling corresponding fields in the ARP packet. 


### Command-line interface

Dnsdeceiver provides a functional interactive shell for real-time operations. No need to perform DNS-spoofing on specified domain? Ok, just restart the utility... ?! NOPE! To avoid an reARPing operation all changes can be done runtime. 


```
Deceiver shell! Type help or ? to list commands.

>help

Documented commands (type help <topic>):
========================================
ad       add_dns  exit  ld        list_dns      q     rd    
add_arp  close    help  list_arp  list_threads  quit  rm_dns
```

#### Commands

`normal`
* `exit` - gracefully shutdown the utility (also `quit`, `q` and `close`). This command shuts down the dnsdeceiver, restores ARP tables (performs reARPing of the network) and removes IP tables config.
* `norearp [OPT]` where OPT is in (1, 0). Set bit tells the program to perform the reARPing of the network right before shutdown. Disabled option quits faster, but incorrect ARP settings are left. 

`[arp]`

* `add_arp [IP]` - adding a new target to the arpspoofer
* `rm_arp [IP]` - removing a target from the arpspoofer
* `list_arp` - performing the ls operation on arp targets (i.e. listing arp targets)

`[dns]`

* `add_dns [domain]:[IP]` - adding a new domain target
* `rm_dns [domain]` - removing a domain target
* `list_dns` - performing the ls operation on dns targets (i.e. listing dns targets)

`utility` (mostly debugging)

* `list_threads` - listing threads run by the utility.

### Standalone ARPspoofer

Script called `arpspoofer.py` may be used as a tool for another network attack that uses ARP-spoofing. To invoke it, simply call `arpspoofer.py`. Check `-h` for more options.

