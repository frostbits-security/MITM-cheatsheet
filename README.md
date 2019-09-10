# MITM-cheatsheet
We tried to put together all known MITM attacks and methods of protection against these attacks. Here is also contains tools for carrying out MITM attacks, some interesting attack cases and some tricks associated with them.

**Note:**  Almost all attack tools, described here, doesn't have any sniffer inside. It only provides attack. Tools for sniffing here: [Data sniffing](#data-sniffing). 

A cheat sheet for pentesters and defensive teams about Man In The Middle attacks.

## Table of Contents  
* [L2](#l2)  
	* [Arp spoofing](#arp-spoofing)
	* [STP(RSTP, PVSTP, MSTP) spoofing](#stprstp-pvstp-mstp-spoofing)   
	* [NDP spoofing](#ndp-spoofing) :hourglass_flowing_sand:  
	* [VLAN hopping](#vlan-hopping)  
* [L3](#l3)  
	* [SLAAC Attack](#slaac-attack)  
	* [Hijacking HSRP (VRRP, CARP)](#hijacking-hsrp-vrrp-carp) :hourglass_flowing_sand:  
	* [Dynamic routing protocol spoofing (BGP)](#dynamic-routing-protocol-spoofing-bgp) :hourglass_flowing_sand:  
	* [RIPv2 Routing Table Poisoning](#ripv2-routing-table-poisoning)  
	* [OSPF Routing Table Poisoning](#ospf-routing-table-poisoning) :hourglass_flowing_sand:  
	* [EIGRP Routing Table Poisoning](#eigrp-routing-table-poisoning)  
	* [ICMP Redirect](#icmp-redirect)  
* [L4+](#l4)  
	* [NetBIOS (LLMNR) spoofing](#netbios-llmnr-spoofing)  
	* [DHCP spoofing](#dhcp-spoofing)  
	* [Rogue DHCP (DHCPv6)](#rogue-dhcp-dhcpv6)  
* [Wireless](#wireless)  
	* [Karma attacks (Wi-Fi)](#karma-attacks-wi-fi)  
	* [Rogue BTS (GSM)](#karma-attacks-wi-fi) :hourglass_flowing_sand:  
* [Attack technics](#attack-technics) :hourglass_flowing_sand:  
	* [Data sniffing](#data-sniffing) :hourglass_flowing_sand:  
	* [Injections in data](#injections-in-data) :hourglass_flowing_sand:  
		* [Malicious JS in HTML](#malicious-js-in-html) :hourglass_flowing_sand:  
		* [HTA](#hta) :hourglass_flowing_sand:  
	* [Data modification](#data-modification) :hourglass_flowing_sand:  
		* [Wsus](#wsus) :hourglass_flowing_sand:  
		* [DNS hijacking](#dns-hijacking) :hourglass_flowing_sand:  
* [Hacker notes](#hacker-notes)   
	* [Difference between CPU (or why most of that attack imposible from your notebook)](#difference-between-cpu-or-why-most-of-that-attack-imposible-from-your-notebook) 
* [SSLStrip, SSLStrip+, HSTS](#sslstrip-sslstrip-hsts) 

:hourglass_flowing_sand: - part in process

## L2

### Arp spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
Address Resolution Protocol (ARP) designed for resolving IP addresses to MAC addresses. All network devices that need to communicate in the network use broadcast ARP queries to find out other machines’ MAC addresses. 
  
Almost all arp spoofing tools use a [gratuitous](http://wiki.wireshark.org/Gratuitous_ARP) arp response. A Gratuitous ARP reply is a reply to without a ARP request. 

Despite the effectiveness of gratuitous ARP, it is particularly insecure because it can be used to assure the remote host that the MAC address of a system on the same network has changed and to specify which address is used now.

<details>
<summary>The typical example of arp spoofing attack</summary>

1. Before ARP-spoofing is performed, there are entries in the ARP tables of nodes A and B with IP and MAC addresses of each other. The information is transmitted between nodes A and B.

2. During the ARP-spoofing process, the С computer performing the attack sends ARP responses (without receiving requests = gratuitous arp) =>  
* to node A: with the IP address of node B and the MAC address of node C;
* to node B: with the IP address of node A and the MAC address of node C.

3. As the computers support gratuitous ARP, they modify their own ARP tables and place records where the MAC address of computer C is instead of the real MAC address of computer A and B.
</details>

Also there is a chance of successful attack in another way. When you will monitor the arp activity in the network segment and suddenly notice the victim's  arp request, you can try send the arp reply to victim faster than addressee of that request. Some vendors can accept this trick. 

**Attack tools:**
* [`bettercap`](https://www.bettercap.org/legacy/)` -T 10.10.10.10 -X --httpd --proxy-https --proxy`  
The old version of the tool is simpler, but there is also a [new](https://github.com/bettercap/bettercap) fashionable one written in Go.
**Note:** Bettercap have excelent sniffer inside.
* [`arpspoof`](http://github.com/smikims/arpspoof)` -i eth0 -t 10.10.10.10`
* [Intercepter-NG](http://sniff.su/) (Now it could be installed at Linux) 

**Attack detection**

* [arpwatch](https://ee.lbl.gov)  
The  program monitors all ARP activity on the selected interfaces. When it notices an anomalies, such as a change in the MAC address while saving the IP address, or vice versa, it reports this to the syslog.
* [XArp](http://www.chrismc.de/)  
Arpwatch for Windows
* [remarp](http://www.raccoon.kiev.ua/projects/remarp/)
Arpwatch via SNMP


**Attack prevention**

* Manual ARP tables  
It has limitation because it will cause difficulties in network scalability. And for wireless network this is a challenge and almost like impossible.

* Patching  
Utilities such as Anticap and Antidote can play a vital role in preventing ARP spoofing where Anticap prevent updating the ARP cache with different MAC with the existing ARP cache which actually prevent the ARP spoofing but it violates the ARP protocol specification which indeed a problem where on the other hand Antidote prevents the ARP poisoning slightly different way. It analyzes the newly received ARP reply with the existing cache. If the new cache differs with the previous then it look for the MAC address if it still alive. If it found the previous cache MAC address alive, rejects the new one and it adds the attacker MAC address in the list of banned MAC address to prevent further attempts from the ARP poisoning on the same target computer.

* Creating a VLAN on the switch  
A VLAN is created on the switch that contains only the switch itself and a specific network device.

* Creating encrypted connections  
This method is also suitable for public networks, because all traffic is encrypted and it is impossible to intercept any user data.

* DAI  
Dynamic ARP inspection in cisco systems helps prevent the man-in-the-middle attacks by not relaying invalid or gratuitous ARP replies out to other ports in the same VLAN. Dynamic ARP inspection intercepts all ARP requests and all replies on the untrusted ports. Each intercepted packet is verified for valid IP-to-MAC bindings via DHCP snooping. Denied ARP packets are either dropped or logged by the switch for auditing so ARP poisoning attacks are stopped. Incoming ARP packets on the trusted ports are not inspected. 

> Related links  
[How ARP works](https://www.tummy.com/articles/networking-basics-how-arp-works/)

### STP(RSTP, PVSTP, MSTP) spoofing
**Сomplexity:** High  
**Relevance:** Moderate  
**Description:**  
The spanning tree protocol is designed to detect and prevent loops in the network if there are redundant paths between the switches.

Anyone who can emulate a device with a (lower) root switch identifier (by connecting a new virtual device with a lower priority or using the STP packet generation tool) can partially or completely intercept the virtual network traffic. Typically, an attacker does not have a physical connection with two switches, so the described attack method is hardly possible. However, in wireless networks, the situation is changing, since the cable connection (socket in the office) and the wireless connection (access point) can end on different switches.

**Attack tools**  
Caution: Often this type of attack leads to a denial of service.

* [`yersinia`](https://github.com/tomac/yersinia)` –G`
Yersinia has a graphical interface and an interactive console, you need to select network interfaces and launch a MITM attack.  
The graphical interface does not work stably, so you can use the interactive interface: `yersinia –I`.
* [`ettercap`](http://ettercap.qithub.lo/ettercap/downloads.html)  
One more tool for Linux. You need to select the interfaces, then tap "stp mangier" plugin and start it.

**Defence technics**  
* Disabling STP on access ports (to stop recieve BDPU from users), enable port security on all user ports, and restricting physical access to network equipment.
* [configuration tools](https://community.cisco.com/t5/networking-documents/spanning-tree-protection/ta-p/3116493) that protect STP (Cisco).

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
A virtual LAN (Local Area Network) is a logical subnetwork that can group together a collection of devices from different physical LANs. Larger business computer networks often set up VLANs to re-partition their network for improved traffic management.

[VLANs](https://en.wikipedia.org/wiki/Virtual_LAN) work by applying tags to network frames and handling these tags in networking systems – creating the appearance and functionality of network traffic that is physically on a single network but acts as if it is split between separate networks. 

VLAN hopping is a common name for attacks that involve access to the VLAN, which was initially (before the attack) unavailable to the attacker.

<details>
<summary>It could be performed in two ways: </summary>

1. The primary VLAN Hopping attack (using [DTP](https://en.wikipedia.org/wiki/Dynamic_Trunking_Protocol))  
Works only on old Cisco switches.  
An attacker acts as a switch in order to trick a legitimate switch into creating a trunking link between them. Packets from any VLAN are allowed to pass through a trunking link. Once the trunk link is established, the attacker then has access to traffic from any VLAN. This method is only successful when the legitimate switch is configured to negotiate a trunk. This occurs when an interface is configured with either "dynamic desirable", "dynamic auto" or "trunk" mode. If the target switch has one of those modes configured, the attacker then can generate a DTP message from their computer and a trunk link can be formed.

2. *Double tagging* occurs when an attacker adds and modifies tags on an Ethernet frame to allow the sending of packets through any VLAN. This attack takes advantage of how many switches process tags. Most switches will only remove the outer tag and forward the frame to all native VLAN ports. With that said, this method is only successful if the attacker belongs to the native VLAN of the trunk link. Another important point is, this attack is strictly one way as it is impossible to encapsulate the return packet. </details>

[The Exploit-db doc](https://www.exploit-db.com/docs/english/45050-vlan-hopping-attack.pdf)  
[The Guide with illustrations and video](https://networklessons.com/cisco/ccnp-switch/vlan-hopping)  
[VLAN hopping full guide](https://www.alienvault.com/blogs/security-essentials/vlan-hopping-and-mitigation)  
[In-depth article](https://learningnetwork.cisco.com/blogs/vip-perspectives/2019/07/12/vlan1-and-vlan-hopping-attack)  


**Attack tools**

* [`yersinia`](https://github.com/tomac/yersinia)` –G`
Yersinia has a graphical interface and an interactive console, you need to select network interfaces and launch a MITM attack.  
The graphical interface does not work stably, so you can use the interactive interface: `yersinia –I`. 

* [Scapy](https://scapy.net/)  
Scapy is a Python program that enables the user to send, sniff and dissect and forge network packets. It can be used to create the specially crafted frames needed for processing this attack.

* [`dtp-spoof.py`](https://github.com/fleetcaptain/dtp-spoof)` -i eth0` sends a DTP Trunk packet out eth0 using eth0's mac address
DTP-spoof is a security tool to test the Dynamic Trunking Protocol (DTP) configuration of switches. If the target switch is configured to negotiate the port mode, you can potentially set the target switch's port to Trunk mode, thereby gaining access to additional VLANs.  
**Defence technics**

1. The primary VLAN Hopping attack (using DTP)  
It can only be performed when interfaces are set to negotiate a trunk. To prevent the VLAN hopping from being exploited, we can do the below mitigations:  
	+ Ensure that ports are not set to negotiate trunks automatically by disabling DTP
	+ Do not configure any access points with either of the following modes: "dynamic desirable", "dynamic auto", or "trunk".
	+ Shutdown all interfaces that are not currently in use.

2. Double Tagging  
To prevent a Double Tagging attack, keep the native VLAN of all trunk ports different from user VLANs.


## L3
### SLAAC Attack 

**Complexity:** Low  
**Relevance:** High  
**Description**  
SLAAC - Stateless Address AutoConfiguration. SLAAC os the one of ways of host network configuration, like DHCPv4. SLAAC provides an IPv6 host prefix value, prefix length and default gateway link-local address without DHCPv6-server which keeps state of the provided addresses (thats why it's called stateless). The SLAAC process is performed during SLAAC-only and SLAAC+DHCPv6 Stateless configuration. 

The main problem of this process is that the attacker can craft the rogue RA to give the hosts his own configuration (e.g., to become a default router on the link). All the hosts, which have IPv6 enabled, are potentially vulnerable to SLAAC attacks. Especially in cases, when IPv6 is enabled is OS by default but organization hasn't deployed IPv6 in any form.

Another threat in RA comes from the ability to send DNS configuration over RA, so that attacker can spoof it, too: [RFC 6106 - IPv6 Router Advertisement Options for DNS Configuration](http://tools.ietf.org/html/rfc6106).  

**Attack Tools**  

* [suddensix](https://github.com/Neohapsis/suddensix)  
It's a script which presets tools used by the security researcher Alec Waters in his [post about SLAAC attack](https://resources.infosecinstitute.com/slaac-attack/). The script is a little bit outdated and working well on Ubuntu 12.04 LTS. It is better to create separated VM for it.

* [EvilFOCA](https://github.com/ElevenPaths/EvilFOCA)  
Amazing tool for windows for IPv6 MITM attacks. A C#-written tool with GUI which allows IPv6 attacks, including SLAAC attack, fake DHCPv6 and even SLAAC DoS which means announcing fake routes in multiple RAs on link.

* [THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)  
A written in C IPv6 attack toolkit which, among many other options, allows to perform attacks with RAs.
 
**Defence technics**  
The simpliest way to mitigate SLAAC-attacks is to just disable IPv6 on all hosts in the network. But this solution is only suitable for networks where IPv6 stack is not in use and was enabled just due to misconfiguration.  

<details>
 <summary>Vendors implementation</summary>

Cisco has implemented a technology "IPv6 First Hop Security" which is included in Catalyst 6500, 4500, 3850, 3750 and 2960 Series Switches, 7600 Series Routers and Cisco 5700 Series Wireless LAN Controllers. There's RA Guard, DHCP Guard and also IPv6 Snooping implemented. More information can be found [here](https://www.cisco.com/c/dam/en/us/products/collateral/ios-nx-os-software/enterprise-ipv6-solution/aag_c45-707354.pdf).  

Juniper has implemented RA Guard. There is one strange fact: on the `router-advertisement-guard` statement [documentation page](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/router-advertisement-guard-edit-fo.html) it's mentioned that only EX Series platforms are supported. But on the page of [Configuring Stateless IPv6 Router Advertisement Guard](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/port-security-ra-guard.html) and [Configuring Stateful IPv6 Router Advertisement Guard](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/port-security-ra-guard-stateful.html) it's mentioned that both EX and some of QFX Series platforms support RA Guard: EX2300(15.1X53-D56), EX2300-VC(15.1X53-D56), EX3400(15.1X53-D55), EX3400-VC(15.1X53-D55), EX4300(16.1R1), EX4300-VC(16.1R1), EX4300 Multigigabit(18.2R1), EX4600(18.3R1), EX4600-VC(18.3R1) and QFX5100(18.2R1), QFX5110(17.2R1), QFX5200(18.2R1).

Mikrotik, unfortunately, hasn't implemented such technologies. Theres's a [presentation](https://mum.mikrotik.com/presentations/PL12/maia.pdf) from Mikrotik Users' Meeting and author advised just to isolate Layer 2 segment of network. No other valuable advices were found. The problem was also [mentioned](https://forum.mikrotik.com/viewtopic.php?t=68004) on the Mikrotik users' forum in 2012. 

Unfortunately, there are methods of traffic analysis hardening, which breaks performance of protections techniques (e.g. hiding the RA in Hob-By-Hop header). There is a [draft RFC](https://tools.ietf.org/html/draft-gont-v6ops-ra-guard-evasion-01) which describes the evasion of RA Guard. The evasion technique is based on usage of IPv6 packet fragmentation. Some additional recommendations on fragmentation are presented in [RFC 6980 - Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery](http://tools.ietf.org/html/rfc6980).  
</details>

<details>
 <summary>10 basic ideas to solve the problem</summary>

[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104) presents 10 basic ideas to solve the problem of Rogue RA. So the section above is just a brief overview of what IETF has to offer as a solution for today:  

1. *Manual Configuration* of IPv6 address and disabling autoconfiguration for RA messages to be ignored.   
For Linux systems `net.ipv6.conf.*` values can be changed:  
	```
    net.ipv6.conf.all.autoconf = 0  
	net.ipv6.conf.all.accept_ra = 0  
	net.ipv6.conf.default.accept_ra=0  
	net.ipv6.conf.all.accept_ra=0  
	net.ipv6.conf.eth0.accept_ra=0 
    ```
	For Mac-OS there is a [guide for IPv6 hardening](http://www.ipv6now.com.au/primers/ERNW_Hardening_IPv6_MacOS-X_v1_0.pdf). But the author faced a problem with parameter responsible for acceptance of RAs in Mac-OS: net.inet6.ip6.accept_rtadv must be set to 0 but its impossible. It's called deprecated in kernel source code and is defined as read-only, but Mac-OS keeps accepting RAs. So, in Mac-OS it's not possible to disable RAs through sysctl. The one thing that can be done is setting up the maximum number of acceptable prefixes and maximum number of acceptable default routers to 1.  

	For Windows there is a command which can be run under admininstrator to disable autoconfoguration:
	```
	netsh interface ipv6 set interface "Local Area Connection" routerdiscovery=disabled  
	```

2. *RA Snooping* in L2 switches similarly to DHCP snooping, so that RAs from wrong sources can be dropped.  

3. *ACLs on Managed Switches* can be used if there is a mechanism of ACL on a switch which can block ICMPv6 RA outbound on user ports(used to access LAN by users). So if such ACL is possible to implement on a used platform, no user on LAN will be able to broadcast/unicast RA.  

4. *SEcure Neighbor Discovery - SEND* - [RFC 3971](https://tools.ietf.org/html/rfc3971) is a protocol, which offers the use of public key cryptography to secure the communications between router and hosts.  

5. *Router Preference Option* - this method is only suitable in case of accidental RAs from users. The idea is that administrator can set "High" level of preference in all legitimate RAs so that IPv6 hosts wont overwrite the configuration received by such RAs if they have "Medium" or "Low" preference level. The Router Preference Option is present in [RFC 4191 - Default Router Preferences and More-Specific Routes](https://tools.ietf.org/html/rfc4191).  

6. *Rely on Layer 2 Admission Control* - the idea is based on relying on deployment of 802.1x so that attackers won't be able to join LAN to send RAs and perform attack.  

7. *Using Host-Based Packet Filters* - if there is an ability to push configuration to users' machines, the host-based packet filters can be configured to accept RAs only from exact IPv6 addresses.  

8. *Using an "Intelligent" Deprecation Tool* - the idea is to observe the link traffic for rogue RAs and to deprecate them for hosts by sending a deprecating RA with rogue router's address in it and router lifetime field set to 0. Attack the attack's traffic.  

9. *Using Layer 2 Partitioning* - the idea is that if each user or system is partitioned into a different Layer 2 medium the impact if some rogue RA can be limited. This method causes software and hardware costs growing.  

10. *Adding Default Gateway/Prefix Options to DHCPv6* - leaving SLAAC autoconfiguration for DHCPv6 autoconfiguration partly solves the problem of default gateways and prefixes sent by rogue RAs but also leads to problems with rogue DHCPv6 servers. The second problem is that RA is still used to inform hosts to use DHCPv6.  

The [4th section of RFC 6104](https://tools.ietf.org/html/rfc6104#section-4) has a table which contains the ways of mitigation suitability for 2 cases of Rogue RA: administrator's mistake and user's mistake.
</details>

**Related Monitoring Tools**  
There are some tools, which can be helpful in rogue RA detection and monitoring:

* [NDPMon](http://ndpmon.sourceforge.net/)   
Allows to choose the following configure options before compilation:  

	`--enable-mac-resolv`  
	  Determine the vendor by OUI in MAC-address.  
	`--enable-countermeasures`  
	  Functionality of response to attacks (no described to which ones and how).  
	`--enable-syslogfilter`  
	  Save syslog to /var/log/ndpmon.lo .  
	`--enable-lnfq`  
	  Use libnetfilter_queue instead of PCAP (have some requirements to be installed and ip6tables rules).  
	`--enable-webinterface`  
	  Post html reports (some web server required as nginx/apache).  

* [Ramond](http://ramond.sourceforge.net/)  
Allows to add MAC-address white list of determined legitimate routers, prefix used for 6to4, and unknown prefixes. Based on this configuration the tool monitors RA traffic to find rogue ones.

* [6MoN](https://www.6monplus.it/)  
Allows to monitor network state, watching the DAD process and NS messages. DAD stands for  Duplicate Address Discovery and it determines if there is and address duplication conflict on the network. NS stands for Neighbor Solicitation(ICMPv6 type 135) and is used to determine a neighbor on the link.

> Related RFCs   
[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104)  
[RFC 6105 - IPv6 Router Advertisement Guard](https://tools.ietf.org/html/rfc6105)  
[RFC 3736 - Stateless Dynamic Host Configuration Protocol (DHCP) Service for IPv6](https://tools.ietf.org/html/rfc3736)  
[RFC 4862 - IPv6 Stateless Address Autoconfiguration (SLAAC)](https://tools.ietf.org/html/rfc4862)  
[RFC 7113 - Implementation Advice for IPv6 Router Advertisement Guard (RA-Guard)](https://tools.ietf.org/html/rfc7113)  
[RFC 8021 - Generation of IPv6 Atomic Fragments Considered Harmful](https://tools.ietf.org/html/rfc8021)  

> Other useful related links  
[Windows machines compromised by default configuration flaw in IPv6](https://resources.infosecinstitute.com/slaac-attack/)  
[Why You Must Use ICMPv6 Router Advertisements](https://community.infoblox.com/t5/IPv6-CoE-Blog/Why-You-Must-Use-ICMPv6-Router-Advertisements-RAs/ba-p/3416)  

### Hijacking HSRP (VRRP, CARP)
**Сomplexity:** High  
**Relevance:** High  
**Description:**  
**Attack tools**  
**Defence technics**  

### Dynamic routing protocol spoofing (BGP)
**Сomplexity:** High  
**Relevance:** High  
**Conditions:**  
**Description:**  
**Attack tools**  
https://github.com/fredericopissarra/t50  
**Defence technics**  

### RIPv2 Routing Table Poisoning
**Сomplexity:** Medium  
**Relevance:** Medium  
**Conditions:**  
RIP implemented;  
RIPv1 in use;  
RIPv2 authentication disabled.  
**Description:**  
There are 3 versions of RIP:
* *RIPv1*: the first version, described in [RFC 1058](https://tools.ietf.org/html/rfc1058);
* *RIPv2*: the improved mainly by adding authentication mechanism version, described in [RFC 2453](https://tools.ietf.org/html/rfc2453);
* *RIPv3* or *RIPng* (next generation): supports IPv6, described in [RFC 2080](https://tools.ietf.org/html/rfc2080).  

The most widely implemented protocol is RIPv2. RIPv1 is not secure at all, as it doesn't support message authentication. There is a good [write up](https://digi.ninja/blog/rip_v1.php) on exploiting RIPv1 by injecting a fake route.  

As specified in RFC 2453, RIPv2 router must exchange routing information every 30 seconds. The idea of attack is to send fake RIP Response messages, which contain the route an attacker needs to inject. Though, there is a special multicast for RIPv2 routers - 224.0.0.9, responses, sent as unicast can be accepted, too. This, for example may harden the detection of the attack, comparing to the case of multicast fake routing propagation. There is a good short [write up](https://microlab.red/2018/04/06/practical-routing-attacks-1-3-rip/) on exploting RIPv2 network with no RIPv2 authentication with Scapy usage examle.  

**Attack tools**  
* [t50](https://gitlab.com/fredericopissarra/t50) - a multi-protocol tool for injecting traffic and for network penetration testing. Among many other protocols, it supports RIP.
  
**Defence technics**  
If router is not configured to authenticate RIPv2 messages, it will accept RIPv1 and RIPv2 unauthenticated messages. The most secure configuration in this way is to set up RIPv2 authentication so that router should not be accepting RIPv1 and v2 unauthenticated messages and so making an unauthenticated router unable to inject a route. This mechanism is described in [RFC 2082 - RIP-2 MD5 Authentication](https://tools.ietf.org/html/rfc2082), but, it describes the usage of MD5, which is acknowledged to be a weak hashing function. The better one, which means the use of SHA-1 is described in [RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822).  

Unfortunately, RIPv2 supports only Plain-text and MD5 Authentication. The first one is useless in case of sniffing the network, MD5 Auth is better in case of a passive attacker, intercepting packets, as it doesn't transfer password in plain text.  
[The Configuration of RIPv2 Authentication guide](https://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13719-50.html#md5) describes how to set this feature on *Cisco* devices.  
The guide for setting MD5 authentication for *Mikrotik* is present [here](https://mikrotik.com/documentation/manual_2.6/Routing/RIP.html).
The guide for setting MD5 authentification on *Juniper* devices is present [here](https://www.juniper.net/documentation/en_US/junos/topics/topic-map/rip-authentication.html).

Also, `passive-interface` feature should be used on the access interfaces, which communicate to end devices.  
[Mikrotik's documentation](https://wiki.mikrotik.com/wiki/Manual:Routing/RIP#Interface) on setting `passive interface` feature.  
[Cisco's documentation](https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/rip-passive-interface) on setting `passive interface` feature.  
[Juniper's documentation](https://www.juniper.net/documentation/en_US/junose15.1/topics/reference/command-summary/passive-interface.html) on setting `passive-interface` feature.  

**Related RFCs:**  
[RFC 1388 - RIP Version 2 Carrying Additional Information](https://tools.ietf.org/html/rfc1388)  
[RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822)  
[RFC 2453 - RIP Version 2](https://tools.ietf.org/html/rfc2453)  
[RFC 2080 - RIPng for IPv6](https://tools.ietf.org/html/rfc2080).  

### OSPF Routing Table Poisoning
**Сomplexity:** High  
**Relevance:** High  
**Conditions:**  
**Description:**  
**Attack tools**  
**Defence technics**  

### EIGRP Routing Table Poisoning
**Complexity:** Medium  
**Relevance:** Medium  
**Conditions:** EIGRP protocol implemented on the network; no EIGRP messages authentication set up  
**Description:**  
EIGRP stands for Enhanced Interior Gateway Routing Protocol. It is a proprietary Cisco’s distance vector routing protocol, relying on Diffused Update Algorithm - DUAL. The main purpose of this protocol is to dynamically update the routing table and propagate the routes to other routers.  
The main security issue is possible in case of spoofing data in *Update* message, e.g. to inject a non-legitimate route. In this case the router's routing table gets changed to make it pass the traffic through the device, controlled by the attacker and so the MitM attack is present.  

**Attack tools**  
* [Eigrp Tools](http://www.hackingciscoexposed.com/?link=tools)  
A perl script which allows to craft EIGRP packets and send them on network. It even allows set the K1-K4 metrics, all the flags and fields of EIGRP packet. The script requires `libnet-rawip-perl` and `libnetpacket-perl` packets to be installed. Some examples of usage:  

	`./eigrp.pl --sniff --iface eth0`  
	  perform a sniff on eth0 interface  
	`./eigrp.pl --file2ip update.dat --source 192.168.7.8`  
	  replay the traffic from file  
	`./eigrp.pl --update --external --as 65534 --source 192.168.7.8`  
	  send and Update message  

* [EIGRP Security Tool](https://sourceforge.net/projects/eigrpsectool/)  
A python script, which allows to craft and send different EIGRP packets. The problem is that attempts to launch the script were unsuccessful due to lack of scapy_eigrp module which wasn't found. Also authors didn't write any documentation for the tool even in the 
[research description](https://docs.google.com/document/d/1ZVNwi5KRkbY_PxMoODTvwSh3qpzdqiRM9Q4qppP2DvE/edit).

* [t50](https://gitlab.com/fredericopissarra/t50) - a multi-protocol tool for injecting traffic and for network penetration testing. Among many other protocols, it supports EIGRP traffic manipulating.

**Defence techniques**  
To protect a network from untrusted route propagations, EIGRP provides a mechanism for authenticating router updates. It uses MD5-keyed digest to sign each packet to prevent unauthorized devices from sending updates to the network. It protects legitimate routers from non-legitimate router updates and from router spoofing. The key is just a defined string, which must be set on other devices which are meant to be legitimate. The detailed guide on EIGRP MD5 Authentication setup can be found [here](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/82110-eigrp-authentication.html#maintask1).  

Unfortunately, MD5 is acknowledged to be a weak hashing algorithm due to hash collisions. Cisco devices also support `hmac-sha-256` EIGRP Updates Authentification. The hash collision attack on SHA-256 is much more complex than for MD5. The guide to EIGRP HMAC-SHA-256 Authentication can be found [here](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-sha-256.pdf).  

The stub EIGRP routing area can be set up as it let's determine the types of routes the stub router should receive queries or not. More information on EIGRP Stub Routing can be found [here](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-eigrp-stub-rtg.html).  

Another best practice to reduce unwanted traffic in a network is to set up passive interfaces. `passive-interface` feature should be set on access interfaces, which communicate not to network devices, but to end devices. The instruction on setting `passive-interface` on EIGRP and explaination on how it works is presented in [Cisco's documentation page](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/13675-16.html).  

### ICMP Redirect
**Сomplexity:** Medium  
**Relevance:** Medium  
**Description:**  
One of the purposes of the ICMP Protocol is to dynamically change the routing table of the end network systems.
Dynamic remote management routing was originally conceived to prevent possible send a message to a non-optimal route, as well as to increase fault tolerance of the Network as a whole. It was assumed that the network segment can be connected to the Internet  through several routers (not through one as it usually happens). In this case, we can address the external network through any of the nearest routers. For example, to *some_host.site* the shortest route passes through the "router A" and to the *another.site* - through the "router B". 

If one of the routers fails, communication with the outside world is possible through another router. 
As the "ICMP Redirest attack", we change the route to some site (DNS Name) in the routing table of node A (victim) so that the traffic from node A to some site goes through hacker PC

**Conditions of success:**  
- The IP address of the new router must be on the same subnet as the attacked host itself.
- A new route cannot be added for an IP address that is on the same subnet as the host itself.
- OS must support and process ICMP redirect packets. By default ICMP redirect enabled in Windows (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect)  
and in some Linux distros (cat /proc/sys/net/ipv4/conf/all/accept_redirects)

**Attack tools**

- [Responder](https://github.com/SpiderLabs/Responder) ([example](https://github.com/SpiderLabs/Responder/blob/master/tools/Icmp-Redirect.py))
- Hping3 ([example](https://gist.github.com/githubfoam/91bd46b68c7ee1fe465e9f743a24d140))
- [Mitmf](https://github.com/byt3bl33d3r/MITMf)
- Bettercap ([documentation](https://www.bettercap.org/legacy/))

**Defence technics**

- Disable icmp redirect ([example](https://sbmlabs.com/notes/icmp_redirect_attack/))

## L4+

### NetBIOS (LLMNR) spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
If a windows client cannot resolve a hostname using DNS, it will use the Link-Local Multicast Name Resolution ([LLMNR](https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10))) protocol to ask neighbouring computers. LLMNR can be used to resolve both IPv4 and IPv6 addresses. 

If this fails, NetBios Name Service ([NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)) will be used. NBNS is a similar protocol to LLMNR that serves the same purpose. The main difference between the two is NBNS works over IPv4 only. 

The problem of this pretty cool thing is that when LLMNR or NBNS are used to resolve a request, any host on the network who knows the IP of the host being asked about can reply. Even if a host replies to one of these requests with incorrect information, it will still be regarded as legitimate.

The attacker may request NTLM authentication from the victim, which will cause the victim's device to send an NTLM hash, which can then be used for brute force attack.

<details>
 <summary>Also there is a chance to perform WPAD spoofing.</summary>

WPAD spoofing can be referred to as a special case of LLMNR- and NBNS-spoofing. Web Proxy Auto Discovery protocol is used for automatic configuration of HTTP proxy server. 

The device sends an LLMNR/NBNS request with a wpad host, obtains the corresponding IP address and tries to access the wpad.dat file containing information about proxy settings via HTTP.

As a result, an attacker can perform LLMNR/NBNS spoofing and provide the victim with his own wpad.dat file, resulting in all HTTP and HTTPS traffic going through the attacker.</details>

[Quick tutorial to grab clear text credentials](https://www.trustedsec.com/2013/07/wpad-man-in-the-middle-clear-text-passwords/)  
[How Microsoft Windows’s name resolution services work and how they can be abused](https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/)

**Attack tools**

* [Responder](https://github.com/SpiderLabs/Responder)  
It can answer LLMNR and NBNS queries giving its own IP address as the destination for any hostname requested. Responder has support for poisoning WPAD requests and serving a valid wpad.dat PAC file.

+ [Mitm6](https://github.com/fox-it/mitm6)  
mitm6 is a pentesting tool which is designed for WPAD spoofing and credential relaying. 

+ [Inveigh](https://github.com/Kevin-Robertson/Inveigh)  
Inveigh is a PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system. 

+ [Metasploit modules](https://github.com/rapid7/metasploit-framework)  
[auxiliary/spoof/llmnr/llmnr_response](https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response),  
[auxiliary/spoof/nbns/nbns_response](https://www.rapid7.com/db/modules/auxiliary/spoof/nbns/nbns_response) 

**Defence technics**

+ Disable LLMNR and NBNS. You can do it using [GPO](https://en.wikipedia.org/wiki/Group_Policy)  
([how to do it here](http://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/))  
+ Create DNS entry with “WPAD” that points to the corporate proxy server. So the attacker won’t be able to manipulate the traffic.  
+ Disable “Autodetect Proxy Settings”


### DHCP spoofing 
**Сomplexity:** Moderate  
**Relevance:** Moderate  
**Description:**    
The purpose of this attack is to *use the attacker's host or device as the default gateway* and to force clients to use a false Domain Name Service (DNS) and a Windows Internet name service (WINS server) configured by the attacker. The attacker's task is to configure a fake DHCP server on the network to provide DHCP addresses to clients and exhausted the pool of IP addresses from other legitimate DHCP servers (DHCP Starvation attack).

**Conditions of success:**

 - The client receives an IP address from a Rogue DHCP server faster
   than from a legitimate DHCP server. 
 - The legitimate server has exhausted the pool of addresses to be issued (DHCP Starvation attack).

 **DHCP Starvation attack**: 

 - The attacker requests an IP address from the DHCP server and receives it
  - The MAC address of the attacker changes and it requests the next, different IP address, masked as a new client
 - These actions are repeated until the entire pool of IP addresses on the server is   exhausted.

**Attack tools for DHCP starvation**
- [DHCPig](https://github.com/kamorin/DHCPig)
- nmap to find DHCP server (`nmap -n --script=broadcast-dhcp-discover`)
- metasploit modules ([example](https://digi.ninja/metasploit/dns_dhcp.php))
- use scapy for DHCP starvation attack ([example](https://github.com/shreyasdamle/DHCP-Starvation-))

**Attack tools for DHCP spoofing**
 - [yersinia](https://kalilinuxtutorials.com/yersinia/)
 - [mitmf](https://github.com/byt3bl33d3r/MITMf)
 - [Ettercap](https://www.ettercap-project.org/)
 
 

**Defence technics**

- *Enable DHCP snooping*

This is a L2 switch function designed to protect against DHCP attacks. For example, a DHCP spoofing attack or DHCP starvation attack.

On Cisco Switches:
- *Switch(config)#ip dhcp snooping vlan 10* - enable DHCP snooping for vlan10 
- *Switch(config)# interface fa 0/1* - go to the settings of the specific interface
- *Switch(config-if)#ip dhcp snooping trust* - setting up trusted ports on the interface (by default all ports are unreliable, the DHCP server should not be connected to them).
- *Switch(config)#ip dhcp-server 10.84.168.253* - Specify the address of the trusted DHCP server, which is accessible through the trusted port.

**Important.** By default, after enabling DHCP snooping, the switch is enabled to check for MAC address matching. The switch checks whether the MAC address in the DHCP request matches the client's MAC address. If they do not match, the switch discards the packet.

> [How DHCP works](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)  
> [DHCP wireshark sample](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=dhcp.pcap)

### Rogue DHCP (DHCPv6)
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
The Ipv6 client sends a *Solicit* message to the All_DHCP_Relay_Agents_and_Servers address to find available DHCP servers. Any server that can meet the client's requirements responds with an *Advertise* message. The client then chooses one of the servers and sends a *Request* message to the server asking for confirmed assignment of addresses and other configuration information.The server responds with a *Reply* message that contains the confirmed addresses and configuration.  

This schema looks simular to DHCPv4 so the main goal for the attacker is to use fake DHCPv6 server to redirect victims traffic to himself.  

The attacker can catch client DHCP solicit message and can actually reply, pretending that he is the DHCPv6 server and assign credentials (such as the DNS address) to be used by victim. 

**Attack tools**

- [mitm6](https://github.com/fox-it/mitm6)
- some scapy python scripts ([example](https://cciethebeginning.wordpress.com/2012/01/27/dhcpv6-fake-attack/))
- [snarf](https://github.com/purpleteam/snarf)

**Defence technics**

- In cisco devices enable dhcpv6 guard policy ([example](https://community.cisco.com/t5/networking-documents/understanding-dhcpv6-guard/ta-p/3147653))
- disable Ipv6 if you don't use it

## Wireless
### Karma attacks (Wi-Fi)

**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
The KARMA attack uses the peculiarities of the clients who send requests to determine which wireless networks are nearby. 

The Wi-Fi Access Point periodically sends a beacon request indicating the network SSID that identifies the Wi-Fi network. When a client receives a beacon frame with an SSID that it remembers, it can be associated with the wireless network.
Vulnerable client devices broadcast a "preferred network list" (PNL), which contains the SSIDs of access points to which they have previously connected and are willing to automatically reconnect without user intervention. These broadcasts may be received by any WiFi access point in range. The KARMA attack consists in an access point receiving this list and then giving itself an SSID from the PNL, thus becoming an evil twin of an access point already trusted by the client.

As a result, the client connects to a different network than the one the user expects. And now the attacker can perform MITM or other attacks on the client system.

*However, nowadays*, most modern network managers have taken countermeasures against the KARMA attack by switching to passive scanning; instead of arbitrarily sending probe request frames, network managers now wait to receive a beacon frame with a familiar ESSID before associating with a wireless network. While this countermeasure has hampered the effectiveness of the KARMA attack, the second feature exploited by KARMA, the Auto-Connect flag that enables the stations to automatically join previously connected networks, was left intact in almost every modern Operating System.

An attacker that can guess the SSID  in the victim device's Preferred Network List, will be able to broadcast the corresponding beacon frame and have that device automatically associate with an attacker-controlled access point. In a more sophisticated version of the attack, the adversary may use a "dictionary" of common SSIDs, that the victim has likely connected to in the past.

[How does a KARMA attack work?](https://www.justaskgemalto.com/en/karma-attack-work-former-ethical-hacker-jason-hart-explains/)

**Attack tools**

+ *[Wifiphisher](https://github.com/wifiphisher/wifiphisher)*  
The Rogue Access Point Framework 

+ *[hostapd-mana](https://github.com/sensepost/hostapd-mana/)*  
Hostapd-mana is a featureful rogue wifi access point tool. It can be used for a myriad of purposes from tracking and deanonymising devices (aka Snoopy), gathering corporate credentials from devices attempting EAP (aka WPE) or attracting as many devices as possible to connect to perform MitM attacks.

+ *[WIFI PINEAPPLE](https://shop.hak5.org/products/wifi-pineapple)*  
The rogue access point and WiFi pentest toolkit.  
How to reinforce the MK5 Karma attack with the Dogma PineAP module [here](https://www.hak5.org/episodes/hak5-gear/the-next-gen-rogue-access-point-pineap).

+ *[FruityWIFI](http://fruitywifi.com/index_eng.html)*  
FruityWiFi is an open source tool to audit wireless networks. It allows the user to deploy advanced attacks by directly using the web interface or by sending messages to it.  
Initialy the application was created to be used with the Raspberry-Pi, but it can be installed on any Debian based system.

**Defence technics**

+ Pay attention to the Wi-Fi networks that your device connects to  
+ Don't use open wifi in public areas, or use it very sparingly  
+ Creating encrypted connections (VPN, etc.)  


### Rogue BTS (GSM)

# Attack technics
## Data sniffing

**Attack tools:**

* [wireshark](https://www.wireshark.org)
* [`net-creds`](https://Qithub.com/DanMcInerney/net-creds)

## Injections in data
### Malicious JS in HTML
### HTA

## Data modification
### Wsus
### DNS hijacking

# Hacker notes
## Difference between CPU (or why most of that attack imposible from your notebook)

When computer networks were slow, the data packets transmitted over them were processed by common CPUs. Everything would have been fine, but with the increasing networks' bandwidth, the performance of these CPUs was not enough. That's when NPUs began to appear, which had a different way of working from general purpose CPUs, but did a great job of processing packets.

So you can't just connect to the network and turn on the spoofing, it can put the network down right away. Your small notebook network adapter simply cannot cope with a large data stream and will start to drop them. You need to choose the optimal number of hosts that you can spoof at the same time(~<4).

### Attack device  
Possible candidate: MikroTik hAP AC

#  SSLStrip, SSLStrip+, HSTS

***SSLStrip*** is a technique that replaces a secure (HTTPS) connection with an open (HTTP) connection.
This attack is also known as HTTP-downgrading

It intercepted HTTP traffic and whenever it spotted redirects or links to sites using HTTPS, it would transparently strip them away.

Instead of the victim connecting directly to a website; the victim connected to the attacker, and the attacker initiated the connection back to the website. The interceptor made the encrypted connection to back to the web server in HTTPS, and served the traffic back to the site visitor unencrypted 

***But*** it doesn't work anymore with the advent of HSTS. More precisely, it doesn't work where HSTS is enabled.

HTTP Strict Transport Security ([HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)) is a web security policy mechanism that helps to protect websites against protocol downgrade attacks (SSL stripping). It allows web servers to declare that web browsers should interact with it using only secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797.

The HSTS works by the server responding with a special header called Strict-Transport-Security which contains a response telling the client that whenever they reconnect to the site, they must use HTTPS. This response contains a "max-age" field which defines how long this rule should last for since it was last seen.

Also It has `includeSubDomains` (optional).
If this optional parameter is specified, this rule applies to all of the site's subdomains as well.

But not everyone sets up HSTS the same way.

That's how ***SSLstrip++*** came about.

It's a tool that transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. 

One of the shortcomings of HSTS is the fact that it requires a previous connection to know to always connect securely to a particular site. When the visitor first connects to the website, they won't have received the HSTS rule that tells them to always use HTTPS. Only on subsequent connections will the visitor's browser be aware of the HSTS rule that requires them to connect over HTTPS.

***HSTS Preload Lists*** are one potential solution to help with these issues, they effectively work by hardcoding a list of websites that need to be connected to using HTTPS-only. 

Inside the source code of Google Chrome, there is a file which contains a hardcoded file listing the HSTS properties for all domains in the Preload List. Each entry is formatted in JSON.


**Attack tools**

+ [sslstrip](https://github.com/moxie0/sslstrip)  
sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks.

+ [sslstrip2](https://github.com/LeonardoNve/sslstrip2)  
This is a new version of [Moxie´s SSLstrip] (http://www.thoughtcrime.org/software/sslstrip/) with the new feature to avoid HTTP Strict Transport Security (HSTS) protection mechanism.

**Defence technics**

[For developers - The 6-Step "Happy Path" to HTTPS](https://www.troyhunt.com/the-6-step-happy-path-to-https/)
