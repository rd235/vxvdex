# VXVDEX

VXVDEX: connect distributed private network namespaces

VXVDEX allows processes running in private network namespaces of hosts in the same LAN (multicast domain) to communicate together.

Features of VXVDEX:
- vxvdex interconnects namespaces whose effective group ownership (egid) are the same
- vxvdex virtual networks are protected from snooping. It is not possible to
tap/intercept packets exchanged by namespaces belonging to a different egid.
In an environment where users have no access to the physical ethernet (cannot plug hosts
to the switches) and run their processes in private network namespaces, vxvdex implements
(safe) virtual VLANs.
- almost zero configuration (user-gid mapping is the only required setting).
- very simple deployment: use vdeplug4 url-address **vxvdex://** when configuring the virtual
machines or Internet of Threads networking stacks joining vxvdex.
(Using further parameters it is possibile to define multiple virtual networks per egid,
use IPv4 or IPv6 encapsulation etc).
- no infrastucture constraints (support for jumbo or
baby giant ethernet packets increase the performance, but vxvdex works using the default MTU, 
although it produces more fragmented packets).
- compatible with vxvde (without the trailing x). 
System administrators can join nodes to the users' vxvdex VLANS using
vxvde and addresses like: **vdvde://grp=1000** or **vxvde://grp=groupname** (these 
refer to the egid 1000 or to the egid named *groupname*, respectively).
- compatible with user namespaces. Users cannot redefine the egid used for virtual networking. 
vxvdex always uses the egid as seen in the *root* namespace.
- vxvdex is fast: bandwidth and delay figures are very close to those reported by vxlan 
(linux kernel implementation).

## Example of usage.

Environment:
- a cluster consisting of several GNU-Linux hosts connected by an Ethernet LAN
- vdeplug4 is installed, including the vxvdex plugin
(see: https://github.com/rd235/vdeplug4)
- the vxvdex.ko kernel module is running on all the hosts
- users work in private networking namespaces (e.g. using libpam-net
		https://github.com/rd235/libpam-net)
- users and groups are shared among all the hosts (e.g. using nis or ldap).

Example:
- Alice (A) and Bob (B) have the following entries in /etc/passwd
```
alice:x:1000:1000:Alice in Wonderland,,,:/home/alice:/bin/bash
bob:x:1001:1001:Bob the Builder,,,:/home/bob:/bin/bash
```

Libpam-net has been installed and both Alice and Bob belong to the group newnet, i.e. in /etc/group there is:
```
newnet:x:148:alice,bob
```

Now when Alice logs in to a hosts of the cluster, she gets a new unconnected stack.
```
alice$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
alice$
```

Alice can run vde compatible virtual machines (kvm, qemu-system\*, virtualbox,
user-mode linux) or Internet of Thread appliances using userland IP stacks
like picoTCP or lwipv6 (e.g. view-os partial virtual machines) using the VDE address **vxvdex://**.
All these virtual networking nodes will be connected together on her VLAN.

Alice can define or migrate her virtual machines on any host of the cluster without worring about the network configuration.
System and network administrators of the Data Center are even less worried, they have to do absolutely **nothing**
to set up the migration.

If Bob can acquire the capability CAP\_NET\_ADMIN on his stack (e.g. his processes are running
		in a user namespace or the capability has been delegated using cado, https://github.com/rd235/cado),
Bob can define a tap interface and directly connect his stack to vxvdex.
```
bob$net_admin# vde_plug -d vxvdex:// tap://eth0
bob$net_admin# ip addr add 10.0.0.1/24 dev eth0
bob$net_admin# ip link set eth0 up
bob$net_admin# ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether ae:32:26:1d:e5:34 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.1/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::ac32:26ff:fe1d:e534/64 scope link 
       valid_lft forever preferred_lft forever
bob$net_admin#
```
(this is just an example, Bob could even set up a dhcp server on a host and let all the stacks and VMs
 acquire their IP addresses as if they were hosts on a LAN).

Now Bob can run his preferred tools enjoing his own VLAN.
```
bob$ iceweasel...
bob$ ssh...
```

## Design of VXVDEX

VXVDEX defines an address family (AF\_VXVDEX) which permits a limited access to the real network.

Vxvdex sockets allow:
- UDP datagrams only (no TCP or other transport layer protocols)
- binding to multicast addresses whose last three bytes have the value of the egid (so multicast domains are independent).
- binding to unicast addresses.
- unicast and multicast packets whose VNI have the same value of egid (vxvdex uses the same header as vxvde and vxlan. 
		Packets using different VNI are not sent and discarded when received).
- setsockopt is limited to the set of features required by the vxvdex plugin and parameters are checked against configuration defined limits,
(e.g. ttl cannot be changed to a higher figure than the max value defined by a kernel module parameter, default is 1).

So user processes (e.g. virtual machines, IoTh network stacks or a vde\_plug) can communicate outside the *cage* of
their networking namespaces but the narrow channel defined by vxvdex's strict rules guarantees that the 
sets of packets generated and/or received by namespaces belonging to different egids have empty intersections.

(c) Renzo Davoli 2016. VirtualSquare Labs. University of Bologna. Italy.
This abstract is protected by the CC-BY-SA-4.0 international license.

## Install VXVDEX

vxvdex has two components:
* a kernel module
* a libvdeplug4 plugin.

prerequisite: vdeplug4

### INSTALL the kernel module:
```
$ cd kernel_module
$ make
$ sudo mkdir -p /lib/modules/$(uname -r)/kernel/misc
$ sudo cp vxvdex.ko /lib/modules/$(uname -r)/kernel/misc
$ sudo depmod -a
```
### INSTALL the libvdeplug4 plugin
```
$ cd libvdeplug_vxvdex
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```
