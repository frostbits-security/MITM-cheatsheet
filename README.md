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

***The typical example of arp spoofing is below:***

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
### SLAAC Attack 
## SLAAC - Stateless Address AutoConfiguration
**Сomplexity:** Low  
**Relevance:** High  
**Description**  
	One of ways of host network configuration, like DHCPv4. SLAAC provides an IPv6 host prefix value, prefix length and default gateway link-local address without DHCPv6-server which keeps state of the provided addresses (thats why it’s called stateless). Participating in SLAAC process, hosts use two ICMPv6 messages. They are Router Advertisement (RA) – ICMPv6 type 134 and Router Solicitation (RS) – ICMPv6 type 133.  
	***Router Solicitation (RS)*** is a message, which is sent by the IPv6 host to the all-router’s multicast address ff02::2. This address is assigned to every router on the link, so every rohuter will receive this RS message. The reply to RS will be the RA – Router Advertisement message and it will be sent to the all-hosts address f02::1 which is used to reach all the hosts on the link.   
	***Router Advertisement (RA)*** is a message which is sent as a reply to the RS or periodically and contains the following configuration information:
* prefix value;  
* prefix length;  
* default router link address;  
* DNS server link address (in case of SLAAC-only).    

<p>There are 3 major ways of network configuration in IPv6:</p>

**SLAAC only** – IPv6 host uses prefix value, prefix length, default router address and DNS server address, which are present in RA message received from router.  
**SLAAC+DHCPv6** – it’s a stateless scheme, too, but IPv6 host takes only prefix value, prefix length and default router address from RA. The rest of configuration information, like DNS server address is meant to be received from DHCPv6 server, which, in this case, is used as an “extra database” to keep additional information.   
**DHCPv6** – the way of configuration which is a stateful method and an analogue of DHCPv4.  
<p>The way the host must receive its network configuration is determined by the host from the router’s RA. There are 4 flags which do the job:</p>

**A-bit** – Autonomous Address Autoconfiguration Flag means that host must use [SLAAC process](http://tools.ietf.org/html/rfc4862) to receive the network configuration.  
**L-bit** – On-Link Flag means that prefix, listed in the RA is the local IPv6 address.  
**M-bit** – Managed Address Config Flag means that host must use a [stateful DHCPv6](http://tools.ietf.org/html/rfc3315) process for configuration – the analogue fro DHCPv4.  
**O-bit** – Other Config Flag means that there are additional configurations details, except prefix value, prefix length and default router address, which the host can receive from DHCPv6 server. [DHCPv6 Stateless](http://tools.ietf.org/html/rfc3736).  
<p>The SLAAC process is performed during SLAAC-only and SLAAC+DHCPv6 Stateless configuration. The main problem of this process is that the attacker can craft the rogue RA to give the hosts his own configuration (e.g., to become a default router on the link). All the hosts, which have IPv6 enabled, are potentially vulnerable to SLAAC attacks. Especially in cases, when IPv6 is enabled is OS by default but organization hasn’t deployed  IPv6 in any form.</p>   
<p>The problem of Rogue RA is covered in [RFC 6104 - Router Advertisement Problem Statement].(https://tools.ietf.org/html/rfc6104) As a solution, IETF proposed a technology called RA Guard, which gives an opportunity to accept legitimate RA from legitimate routers and block malicious RA. There are two main RFCs, which rely to this technology:</p>   

* [RFC 6105 - IPv6 Router Advertisement Guard](https://tools.ietf.org/html/rfc6105)
* [RFC 7113 - Implementation Advice for IPv6 Router Advertisement Guard (RA-Guard)](https://tools.ietf.org/html/rfc7113)
	
<p>Cisco has implemented a technology “IPv6 First Hop Security” which is included in Catalyst 6500, 4500, 3850, 3750 and 2960 Series Switches, 7600 Series Routers and Cisco 5700 Series Wireless LAN Controllers. There’s RA Guard, DHCP Guard and also IPv6 Snooping implemented. More information can be found [here](https://www.cisco.com/c/dam/en/us/products/collateral/ios-nx-os-software/enterprise-ipv6-solution/aag_c45-707354.pdf).</p>
<p>Unfortunately, there are methods of traffic analysis hardening, which breaks performance of protections techniques (e.g. hiding the RA in Hob-By-Hop header). There is a [draft RFC](https://tools.ietf.org/html/draft-gont-v6ops-ra-guard-evasion-01) which describes the evasion of RA Guard. The evasion technique is based on usage of IPv6 packet fragmentation. Some additional recommendations on fragmentation are presented in [RFC 6980 - Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery](http://tools.ietf.org/html/rfc6980).</p>
<p>Another threat in RA comes from the ability to send DNS configuration over RA, so that attacker can spoof it, too: [RFC 6106 - IPv6 Router Advertisement Options for DNS Configuration](http://tools.ietf.org/html/rfc6106).</p>

**Related Monitoring Tools**  
There are some tools, which can be helpful in rogue RA detection and monitoring:

* [***NDPMon***](http://ndpmon.sourceforge.net/)  
Allows to choose the following configure options before compilation:

    --enable-mac-resolv
	Determine the vendor by OUI in MAC-address.
    --enable-countermeasures
	Functionality of response to attacks (no described to which ones and how).
    --enable-syslogfilter
	Save syslog to /var/log/ndpmon.lo .
    --enable-lnfq
	Use libnetfilter_queue instead of PCAP (have some requirements to be installed and ip6tables rules).
    --enable-webinterface
	Post html reports (some web server required as nginx/apache).

* [***Ramond***](http://ramond.sourceforge.net/)  
	Allows to add MAC-address white list of determined legitimate routers, prefix used for 6to4, and unknown prefixes. Based on this configuration the tool monitors RA traffic to find rogue ones.

* [***6MoN***] (https://www.6monplus.it/)  
	Allows to monitor network state, watching the DAD process and NS messages. DAD stands for  Duplicate Address Discovery and it determines if there is and address duplication conflict on the network. NS stands for Neighbor Solicitation(ICMPv6 type 135) and is used to determine a neighbor on the link.

**Attack Tools**  

* [***suddensix***](https://github.com/Neohapsis/suddensix)  
It’s a script which presets tools used by the security researcher Alec Waters in his post about SLAAC attack (https://resources.infosecinstitute.com/slaac-attack/).

* [***EvilFOCA***](https://github.com/ElevenPaths/EvilFOCA)  
	A C#-written tool with GUI which allows IPv6 attacks, including SLAAC attack, fake DHCPv6 and even SLAAC DoS which means announcing fake routes in multiple RAs on link.

* [***THC-IPv6***](https://github.com/vanhauser-thc/thc-ipv6)  
	A written in C IPv6 attack toolkit which, among many other options, allows to perform attacks with RAs.
 
**Defence technics**  
The simpliest way to mitigate SLAAC-attacks is to just disable IPv6 on all hosts in the network. But this solution is only suitable for networks where IPv6 stack is not in use and was enabled just due to misconfiguration.  

[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104) presents 10 basic ideas to solve the problem of Rogue RA. So the section above is just a brief overview of what IETF has to offer as a solution for today:  
* **Manual Configuration** of IPv6 address and disabling autoconfiguration for RA messages to be ignored.   
<u>For Linux</u> systems net.ipv6.conf.* values can be changed:


	net.ipv6.conf.all.autoconf = 0  
	net.ipv6.conf.all.accept_ra = 0  
	net.ipv6.conf.default.accept_ra=0  
	net.ipv6.conf.all.accept_ra=0  
	net.ipv6.conf.eth0.accept_ra=0  

<u>For Mac-OS</u> there is a [guide for IPv6 hardening](http://www.ipv6now.com.au/primers/ERNW_Hardening_IPv6_MacOS-X_v1_0.pdf). But the author faced a problem with parameter responsible for acceptance of RAs in Mac-OS: net.inet6.ip6.accept_rtadv must be set to 0 but its impossible. It’s called deprecated in kernel source code and is defined as read-only, but Mac-OS keeps accepting RAs. So, in Mac-OS it’s not possible to disable RAs through sysctl. The one thing that can be done is setting up the maximum number of acceptable prefixes and maximum number of acceptable default routers to 1.  

<u>For Windows</u> there is a command which can be run under admininstrator to disable autoconfoguration:

	netsh interface ipv6 set interface "Local Area Connection" routerdiscovery=disabled  

* **RA Snooping** in L2 switches similarly to DHCP snooping, so that RAs from wrong sources can be dropped.  

* **ACLs on Managed Switches** can be used if there is a mechanism of ACL on a switch which can block ICMPv6 RA outbound on user ports(used to access LAN by users). So if such ACL is possible to implement on a used platform, no user on LAN will be able to broadcast/unicast RA.  

* **SEcure Neighbor Discovery – SEND** - [RFC 3971](https://tools.ietf.org/html/rfc3971) is a protocol, which offers the use of public key cryptography to secure the communications between router and hosts.  

* **Router Preference Option** - this method is only suitable in case of accidental RAs from users. The idea is that administrator can set “High” level of preference in all legitimate RAs so that IPv6 hosts wont overwrite the configuration received by such RAs if they have “Medium” or “Low” preference level. The Router Preference Option is present in [RFC 4191 - Default Router Preferences and More-Specific Routes](https://tools.ietf.org/html/rfc4191).  

* **Rely on Layer 2 Admission Control** - the idea is based on relying on deployment of 802.1x so that attackers won’t be able to join LAN to send RAs and perform attack.  

* **Using Host-Based Packet Filters** - if there is an ability to push configuration to users’ machines, the host-based packet filters can be configured to accept RAs only from exact IPv6 addresses.  

* **Using an "Intelligent" Deprecation Tool** - the idea is to observe the link traffic for rogue RAs and to deprecate them for hosts by sending a deprecating RA with rogue router’s address in it and router lifetime field set to 0. Attack the attack’s traffic.  

* **Using Layer 2 Partitioning** - the idea is that if each user or system is partitioned into a different Layer 2 medium the impact if some rogue RA can be limited. This method causes software and hardware costs growing.  

* **Adding Default Gateway/Prefix Options to DHCPv6** - leaving SLAAC autoconfiguration for DHCPv6 autoconfiguration partly solves the problem of default gateways and prefixes sent by rogue RAs but also leads to problems with rogue DHCPv6 servers. The second problem is that RA is still used to inform hosts to use DHCPv6.  

The [4th section of RFC 6104](https://tools.ietf.org/html/rfc6104#section-4) has a table which contains the ways of mitigation suitability for 2 cases of Rogue RA: administrator’s mistake and user’s mistake.

**Related RFCs**  
[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104)  
[RFC 6105 - IPv6 Router Advertisement Guard](https://tools.ietf.org/html/rfc6105)  
[RFC 3736 - Stateless Dynamic Host Configuration Protocol (DHCP) Service for IPv6](https://tools.ietf.org/html/rfc3736)  
[RFC 4862 - IPv6 Stateless Address Autoconfiguration (SLAAC)](https://tools.ietf.org/html/rfc4862)  
[RFC 7113 - Implementation Advice for IPv6 Router Advertisement Guard (RA-Guard)](https://tools.ietf.org/html/rfc7113)  
[RFC 8021 - Generation of IPv6 Atomic Fragments Considered Harmful](https://tools.ietf.org/html/rfc8021)  

**Other useful related links**  
[Windows machines compromised by default configuration flaw in IPv6](https://resources.infosecinstitute.com/slaac-attack/)  
[Why You Must Use ICMPv6 Router Advertisements](https://community.infoblox.com/t5/IPv6-CoE-Blog/Why-You-Must-Use-ICMPv6-Router-Advertisements-RAs/ba-p/3416)  

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
