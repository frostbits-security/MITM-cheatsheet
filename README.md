# MITM_Bible
We tried to put together all known MITM attacks and methods of protection against these attacks. Here is also contains tools for carrying out MITM attacks, some interesting attack cases and some tricks associated with them.

A cheat sheet for pentesters and defensive teams about Man In The Middle attacks.

## L2
### Arp spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:** 

Address Resolution Protocol (ARP) is a  protocol used for resolving IP addresses to machine MAC addresses. All network devices that need to communicate on the network broadcast ARP queries in the system to find out other machines’ MAC addresses.
  
Here is how ARP works:

1. When one machine needs to communicate with another, it looks up its ARP table.
2. If the MAC address is not found in the table, the ARP-request is broadcasted over the network.
3. All machines on the network will compare this IP address to MAC address.
4. If one of the machines in the network identifies this address, then it will respond to the ARP-request with its IP and MAC address.
The requesting computer will store the address pair in its ARP table and communication will take place.

All the arp spoofing tools use a gratuitous arp request([wiki.wireshark](http://wiki.wireshark.org/Gratuitous_ARP) and [with pictures](https://www.practicalnetworking.net/series/arp/gratuitous-arp/)). A gratuitous ARP reply is a reply to which no request has been made.

Gratuitous ARPs are useful for four reasons:

+ They can help detect IP conflicts; 
+ They assist in the updating of other machines' ARP tables
+ They inform switches of the MAC address of the machine on a given switch port;
+ They can notice that an IP interface goes up.

Despite the effectiveness of gratuitous ARP, it is particularly insecure because it can be used to assure the remote host that the MAC address of a system on the same network has changed and to specify which address is used now.

The typical example of arp spoofing is below:

Before ARP-spoofing is performed, there are entries in the ARP tables of nodes A and B with IP and MAC addresses of each other. The information is transmitted between nodes A and B.

During the ARP-spoofing process, the С computer performing the attack sends ARP responses (without receiving requests = gratuitous arp) =>

to node A: with the IP address of node B and the MAC address of node C;

to node B: with the IP address of node A and the MAC address of node C.

As the computers support gratuitous ARP, they modify their own ARP tables and place records where the MAC address of computer C is instead of the real MAC address of computer A and B.

Also there is a chance of successful attack in another way. When you will monitor the arp activity in the network segment and suddenly notice the victim's  arp request, you can try send the arp reply to victim faster than addressee of that request. Some vendors can accept this trick.

**Attack tools:**
+ [Bettercap](https://github.com/bettercap/bettercap) (how to use → [here](https://danielmiessler.com/study/bettercap/))
+ [Arpspoof](http://github.com/smikims/arpspoof)
+ [Cain & Abel](https://github.com/xchwarze/Cain)
+ [Dsniff](https://monkey.org/~dugsong/dsniff/)
+ [Intercepter-NG](http://sniff.su/) (Now it could be installed at Linux) 

**Defence technics:**

1. Attack detection:

+ ***Arpwatch***

The [arpwatch](https://ee.lbl.gov) program monitors all ARP activity on the selected interfaces. When it notices an anomalies, such as a change in the MAC address while saving the IP address, or vice versa, it reports this to the syslog.
Also there are some similar utilities:
+ [XArp](http://www.chrismc.de/)  (arpwatch for Windows)
+ [remarp](http://www.raccoon.kiev.ua/projects/remarp/)  (arpwatch via SNMP)


2. Attack prevention

+ ***Static MAC addresses implement***

It has limitation because it will cause difficulties in network scalability. And for wireless network this is a challenge and almost like impossible.
+ ***Patching***

Utilities such as Anticap and Antidote can play a vital role in preventing ARP spoofing where Anticap prevent updating the ARP cache with different MAC with the existing ARP cache which actually prevent the ARP spoofing but it violates the ARP protocol specification which indeed a problem where on the other hand Antidote prevents the ARP poisoning slightly different way. It analyzes the newly received ARP reply with the existing cache. If the new cache differs with the previous then it look for the MAC address if it still alive. If it found the previous cache MAC address alive, rejects the new one and it adds the attacker MAC address in the list of banned MAC address to prevent further attempts from the ARP poisoning on the same target computer.

+ ***Creating a VLAN on the switch***

A VLAN is created on the switch that contains only the switch itself and a specific network device.
Creating encrypted connections (PPPoE, VPN, etc.)
This method is also suitable for public networks, because all traffic is encrypted and it is impossible to intercept any user data.
+ ***DAI***

Dynamic ARP inspection in cisco systems helps prevent the man-in-the-middle attacks by not relaying invalid or gratuitous ARP replies out to other ports in the same VLAN. Dynamic ARP inspection intercepts all ARP requests and all replies on the untrusted ports. Each intercepted packet is verified for valid IP-to-MAC bindings via DHCP snooping. Denied ARP packets are either dropped or logged by the switch for auditing so ARP poisoning attacks are stopped. Incoming ARP packets on the trusted ports are not inspected. 



### STP(RSTP, PVSTP, MSTP) spoofing
**Сomplexity:** High  
**Relevance:** Moderate  
**Description:**

**Attack tools**

**Defence technics**

### NetBIOS (LLMNR) spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:**

**Attack tools**

**Defence technics**

#### Fake WPAD Server

### Dynamic Trunking Protocol (DTP)
**Сomplexity:** Moderate  
**Relevance:** None  
**Description:**

**Attack tools**

**Defence technics**

### NDP spoofing
**Сomplexity:** Moderate  
**Relevance:** Close to None  
**Description:**

**Attack tools**

**Defence technics**

### VLAN hopping
**Сomplexity:** Moderate  
**Relevance:** None  
**Description:**

**Attack tools**

**Defence technics**

## L3
## SLAAC attack 
**Сomplexity:** High  
**Relevance:** High  
**Description:**

**Attack tools**

**Defence technics**

### Hijacking HSRP (VRRP, CARP)
**Сomplexity:** High  
**Relevance:** High  
**Description:**

**Attack tools**

**Defence technics**

### Dynamic routing protocol spoofing (EIGRP, OSPF, BGP)
**Сomplexity:** High  
**Relevance:** High  
**Description:**

**Attack tools**  
https://github.com/fredericopissarra/t50

**Defence technics**

### ICMP Redirect
**Сomplexity:** Moderate  
**Relevance:** None  
**Description:**

**Attack tools**

**Defence technics**

## L4+
### DHCP spoofing 
**Сomplexity:** Moderate  
**Relevance:** Moderate  
**Description:**

**Attack tools**

**Defence technics**

### Rogue DHCP (DHCPv6)
**Сomplexity:** Low  
**Relevance:** High  
**Description:**

**Attack tools**

**Defence technics**

## Wireless
### Karma attacks (Wi-Fi)
### Rogue BTS (GSM)

# Attack technics
## Data sniffing

## Injections in data
### Malicious JS in HTML
### HTA

## Data modification
### Wsus
### DNS hijacking

# Hacker notes
## Difference between CPU (or why most of that attack imposible from your notebook)
### Attack device  
Possible candidate: MikroTik hAP AC

# SSL strip

# For developers
## HSTS
