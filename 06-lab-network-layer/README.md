# Network-Layer Lab

The objective of this assignment is to give you hands-on experience with the
network layer and how it interacts with the link layer.  To accomplish this,
you will implement the Address Resolution Protocol (ARP), forwarding tables,
and a router!

# Table of Contents
 - [Getting Started](#getting-started)
   - [Maintain Your Repository](#maintain-your-repository)
   - [Update Cougarnet](#update-cougarnet)
   - [Resources Provided](#resources-provided)
 - [Part 1 - Address Resolution Protocol (ARP)](#part-1---address-resolution-protocol-arp)
   - [Scenario Description](#scenario-description)
   - [Starter Commands](#starter-commands)
   - [Frames Issued](#frames-issued)
   - [Instructions](#instructions)
   - [Testing](#testing)
   - [Helps](#helps)
 - [Part 2 - Forwarding Table](#part-2---forwarding-table)
   - [Getting Started](#getting-started-1)
   - [Instructions](#instructions-1)
 - [Part 3 - IP Forwarding](#part-3---ip-forwarding)
   - [Scenario Description](#scenario-description-1)
   - [Starter Commands](#starter-commands-1)
   - [Packets Issued](#packets-issued)
   - [Instructions](#instructions-2)
   - [Testing](#testing-1)
   - [Helps](#helps-1)
 - [Automated Testing](#automated-testing)
 - [Evaluation](#evaluation)
 - [General Helps](#general-helps)
 - [Looking Ahead (Optional)](#looking-ahead-optional)
   - [Add Ethernet Switch](#add-ethernet-switch)
   - [Handle IP Broadcasts](#handle-ip-broadcasts)
 - [Submission](#submission)


# Getting Started

## Maintain Your Repository

 Before beginning:
 - [Mirror the class repository](../01b-hw-private-repo-mirror), if you haven't
   already.
 - [Merge upstream changes](../01b-hw-private-repo-mirror#update-your-mirrored-repository-from-the-upstream)
   into your private repository.

 As you complete the assignment:
 - [Commit changes to your private repository](../01b-hw-private-repo-mirror#commit-and-push-local-changes-to-your-private-repo).


## Update Cougarnet

Make sure you have the most up-to-date version of Cougarnet installed by
running the following in your `cougarnet` directory:

```
$ git pull
$ python3 setup.py build
$ sudo python3 setup.py install
```

Remember that you can always get the most up-to-date documentation for
Cougarnet [here](https://github.com/cdeccio/cougarnet/blob/main/README.md).


## Resources Provided

The files given to you for this lab are the following:
 - `host.py` - a file containing a stub implementation of a host (and router).
   This is where you will do your work!
 - `prefix.py` - a file containing a stub code for IP address comparison and
   testing whether an IP address is a member of a subnet.  You will also do
   your work here!
 - `forwarding_table.py` - a file containing a stub implementation of an IP
   forwarding table.  You will also do your work here!
 - `scenario1.cfg` and `scenario2.cfg` -
   [network configuration files](https://github.com/cdeccio/cougarnet/blob/main/README.md#network-configuration-file)
   describing two topologies for testing different aspects of functionality
   related to this lab.
 - `scenario1.py` and `scenario2.py` -
   scripts that run various tests in conjunction with the network configuration
   files.


# Part 1 - Address Resolution Protocol (ARP)

In this part of the lab, you will develop a working ARP implementation for your
hosts and routers.

## Scenario Description

The file `scenario1.cfg` describes a network with three hosts and one router:
`a`, `b`, and `r1` connected to switch `s1`, and `c` and `r1` connected to
switch `s2`.  The topology looks like this:

```
          +----+
          | a  |
          +----+
            |
            |
            |
+---+     +----+
| b | --- | s1 |
+---+     +----+
            |
            |
            |
          +----+
          | r1 | -+
          +----+  |
          +----+  |
          | c  |  |
          +----+  |
            |     |
            |     |
            |     |
          +----+  |
          | s2 | -+
          +----+
```

The switch is a working switch; you do not have to implement its functionality!
Your focus is on the host/router functionality.


## Starter Commands

Take a look at the contents of `scenario1.cfg`.  Then run the following to
start it up:

Run the following command:

```
$ cougarnet --disable-ipv6 --display scenario1.cfg
```

After a few seconds of awkward silence, you will see output on the terminal
corresponding to Host `a`.  The output is made by placeholder code in
`host.py`.  Instead of sending packets, it simply prints out that that's what
it would do.  What is missing at this point is:

 - a mechanism to map the IP address of the next hop to a MAC address - ARP!;
 - an Ethernet frame header to encapsulate the IP packet; and
 - some logic to determine which frames should be acted upon

When these things are added, you will be able to send IP packets across a local
area network (LAN), as long as you know the outgoing interface and the next-hop
IP address.  We will learn how to determine outgoing interface and next-hop in
the [Part 3](#part-3---ip-forwarding).


## Frames Issued

With `scenario1.cfg`, the `send_packet_on_int()` is called for the following
packets at the following times (note that times are approximate).  Each
sub-bullet describes the purpose of the primary bullet under which it is
listed.

 - 4 seconds: packet sent from `a` to `b`
   - There is initially no ARP entry for `b`'s IP address in `a`'s table.
   - `a`'s ARP request should be seen by all hosts on the same LAN.
   - After the ARP response is received by `a`, the ICMP packet from `a` should
     be seen by (only) `b`.
 - 6 seconds: packet sent from `a` to `b`
   - There is already an ARP entry for `b`'s IP address in `a`'s table.
   - The ICMP packet from `a` should be seen by (only) `b`.
 - 8 seconds: packet sent from `b` to `a`
   - There is already an ARP entry for `a`'s IP address in `b`'s table (from
     the previous ARP request).
   - The ICMP packet from `b` should be seen by (only) `a`.
 - 10 seconds: packet sent from `a` to `c` (next hop: `r1`)
   - There is initially no ARP entry for `r1`'s IP address in `a`'s table.
   - `a`'s ARP request should be seen by all hosts on the same LAN.
   - After the ARP response is received by `a`, the ICMP packet from `a` should
     be seen by (only) `r1`.
   - The ICMP packet from `a` should be seen by (only) `r1`. Once IP forwarding
     is working (Part 3), then `c` will also see the packet.


## Instructions

In the file `host.py`, flesh out following the skeleton methods related to ARP:

 - `send_packet_on_int()`.  This method takes the following as arguments:

   - `pkt`: an IP packet, complete with IP header.  Generally, this could be
     either an IPv4 or an IPv6 packet, but for the purposes of this lab, it
     will just be IPv4.
   - `intf`: the name of an interface on the host, on which the packet will be
     sent.
   - `next_hop`: the IP address of the next hop for to the packet, which is
     either the IP destination--if on the same subnet as the host--or the IP
     address of a router.

   The method should do the following:

   - Find the MAC address corresponding to `next_hop`, the next-hop IP address.
     To do this, it should check the host-wide ARP table to see if a mapping
     already exists.

     If a mapping exists, then it can simply build an Ethernet frame consisting
     of:

     - Destination MAC address: the MAC address corresponding to the next-hop
       IP address.
     - Source MAC address: the MAC address corresponding to the outgoing
       interface.  This can be found by retrieving interface information with
       the `interface_info_single()` method
       [here](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames).
     - Type IP (`ETH_P_IP = 0x0800`)
     - The IP packet as the Ethernet payload.

     Then it can send that frame by calling the `send_frame()` method (which is
     defined in the parent class).

     If no mapping exists, then it does the following:

     - queue the packet, along with interface and next hop, for later sending
     - create an [ARP request](#arp-packets), such that:
       - The sender IP address is the IP address associated with the outgoing
         interface.  This can be found by retrieving address information for
         the interface with the `ipv4_address_info_single()`
         [method](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames)
         of the host.
       - The sender MAC address is the MAC address corresponding to the outgoing
         interface (found by retrieving the interface information with the
         `interface_info_single()` method).
       - The target IP address is the next-hop IP address.
       - The target MAC address is all zeroes (this field is ignored by the receiver).
       - The opcode is request (`ARPOP_REQUEST = 1`).

     - build and send an Ethernet frame containing the ARP request, consisting
       of:
       - Destination MAC address: the Ethernet broadcast address:
         (`ff:ff:ff:ff:ff:ff`)
       - Source MAC address: the MAC address corresponding to the outgoing
         interface (found by retrieving the interface information with the
         `interface_info_single()` method).
       - Type ARP (`ETH_P_ARP =  0x0806`)
       - The ARP request as the Ethernet payload.

     The IP packet will get sent later, when the ARP response is received.

 - `handle_arp()`.  This method takes the following as arguments:

   - `pkt` - the ARP packet received
   - `intf` - the interface on which it was received

   This method is called when an Ethernet frame is received by a node, and the
   type field of the Ethernet frame header indicates that the Ethernet payload
   is an ARP packet (i.e., its `type` is `ETH_P_ARP`).

   The method should do the following:

   - Determine whether the ARP packet is an ARP request or an ARP response
     (i.e., using the opcode field), then call `handle_arp_response()` or
     `handle_arp_request()` accordingly.

 - `handle_arp_request()`.  This method takes the same arguments as
   `handle_arp()`:

   The method should do the following:

   - Extract the IP address and MAC address of the sender.
   - Update its own ARP table with an entry that maps the IP address of the
     sender to the MAC address of the sender.
   - If the target IP address matches an IPv4 address on the incoming
     interface, `intf`, then create an ARP response such that:
     - The sender and target IP addresses are reversed.
     - The sender MAC address is used as the target MAC address.
     - The MAC address of the incoming interface is used as the sender MAC
       address.
     - The opcode is reply (`ARPOP_REPLY = 2`).
   - build and send an Ethernet frame containing the ARP response, consisting
     of:
     - Destination MAC address: the MAC address of the entity that sent the
       request sender (i.e., matching the target address in the ARP response).
     - Source MAC address: the MAC address corresponding to the interface on
       which the request was received (and which will also be the outgoing
       interface).
     - Type ARP (`ETH_P_ARP = 0x0806`)
     - The ARP response packet as the Ethernet payload.

 - `handle_arp_response()`.  This method takes the same arguments as
   `handle_arp()`.

   The method should do the following:

   - Extract the IP address and MAC address of the sender.
   - Update its ARP table with an entry that maps the IP address of the
     sender to the MAC address of the sender.
   - Go through its queue of packets that were waiting for this ARP response,
     i.e., those whose next hop corresponds to the sender IP address in the
     response. Send all these packets, by encapsulating each an an Ethernet
     frame (now that you know the destination MAC address!).  See
     `send_packet_on_int()` (the part of the instructions that are specific
     to finding a matching entry in the ARP table) for how to do this.

 - `_handle_frame()`.  This method takes the following as arguments:

   - `frame` - the Ethernet frame received
   - `intf` - the interface on which it was received

   The method should do the following:

   - Extract the destination MAC address in the frame.
   - If the destination MAC address either matches the MAC address
     corresponding to the interface on which it was received or is the
     broadcast MAC address (`ff:ff:ff:ff:ff:ff`), then call another method to
     handle the payload, depending on its type:
     - For type `ETH_P_IP`, extract the payload and call `handle_ip()`, passing
       the Ethernet payload and the interface on which it arrived.
     - For type `ETH_P_ARP`, extract the payload and call `handle_arp()`,
       passing the Ethernet payload and the interface on which it arrived.
     - For all other types, take no further action.
   - If the destination address does not match or is not the Ethernet
     broadcast, then call `not_my_frame()`, passing it the full frame and the
     interface on which it arrived.

 - `not_my_frame()`.  There is no need to flesh out this method.  It is simply
   a placeholder for debugging.


## Testing

Test your implementation against scenario 1.  Determine the appropriate
output--that is, which hosts should receive which frames--and make sure that
the cougarnet output matches appropriately.

When it is working properly, test also with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1.cfg
```


## Helps

### Ethernet Frames

See the documentation for the Link-Layer lab for
[additional helps for Ethernet frames](../04-lab-link-layer/README.md#ethernet-frames).


### Working with `bytes` Instances

See the documentation for the Link-Layer lab for
[additional helps on working with bytes instances](../04-lab-link-layer/README.md#working-with-bytes-instances).


### ARP Packets

Your code will need to both create ARP packets for sending and parse ARP
packets that have been received on the "wire".  ARP packets have the following
format:

<table border="1">
<tr>
<th>00</th><th>01</th><th>02</th><th>03</th><th>04</th><th>05</th><th>06</th><th>07</th>
<th>08</th><th>09</th><th>10</th><th>11</th><th>12</th><th>13</th><th>14</th><th>15</th>
<th>16</th><th>17</th><th>18</th><th>19</th><th>20</th><th>21</th><th>22</th><th>23</th>
<th>24</th><th>25</th><th>26</th><th>27</th><th>28</th><th>29</th><th>30</th><th>31</th></tr>
<tr>
<td colspan="16">Hardware type</td>
<td colspan="16">Protocol type</td></tr>
<tr>
<td colspan="8">Hardware address length</td>
<td colspan="8">Protocol address length</td>
<td colspan="16">Opcode</td></tr>
<tr>
<td colspan="32">Source hardware address :::</td></tr>
<tr>
<td colspan="32">Source protocol address :::</td></tr>
<tr>
<td colspan="32">Destination hardware address :::</td></tr>
<tr>
<td colspan="32">Destination protocol address :::</td></tr>
<tr>
<td colspan="32">Data :::</td></tr>
</table>

Regarding the fields:
 - Hardware Type will always be Ethernet (`ARPHRD_ETHER = 1`)
 - Protocol Type will always be IPv4 (`ETH_P_IP = 0x0800`)
 - Hardware Address Length will always be 6 (MAC addresses are six bytes
   long)
 - Protocol Address Length will always be 4 (IPv4 addresses are four bytes
   long)
 - Operation (or opcode) will either be request (`ARPOP_REQUEST = 1`) or reply
   (`ARPOP_REPLY = 2`).
 - The length of the hardware and protocol addresses will match the value of
   the Hardware Address Length and Protocol Address Length fields--that is, 6
   and 4, respectively.  They are shown as variable length (`:::`) because they
   could be applied to hardware other than Ethernet and protocols other than
   IPv4.
 - While "Hardware" and "Protocol" are the more generic terms for the fields,
   they are referred to in the instructions as "MAC" and "IP" since those are
   the protocols we are working with.


### Address Representation Conversion

To help you with converting MAC addresses and IP addresses from presentation
(i.e., human readable) format to binary (i.e., machine/network readable)
format and vice-versa, I have created four functions for you, which are already
imported in your `host.py`:

 - `mac_binary_to_str()` - takes a `bytes` instance of a MAC address and
   returns a `str` instance with the MAC address in human-readable format.
 - `mac_str_to_binary()` - takes a `str` instance of a MAC address in
   human-readable format and returns a `bytes` instance of the MAC address.
 - `ip_binary_to_str()` - takes a `bytes` instance of an IP address and
   returns a `str` instance with the IP address in human-readable format.
 - `ip_str_to_binary()` - takes a `str` instance of an IP address in
   human-readable format and returns a `bytes` instance of the IP address.


# Part 2 - Forwarding Table

In this part of the lab, you will create a working forwarding table for use in
your hosts and routers.


## Getting Started

Take a look at both `prefix.py` and `forwarding_table.py`.  Both have starter
code that needs to be fleshed out.  But that starter code comes after a lot of
other stuff at the beginning of the file.  This other stuff is doctests.
[doctests](https://docs.python.org/3/library/doctest.html), are "pieces
of text that look like interactive python sessions" (i.e., starting with
`>>>`), found in the [docstring](https://www.python.org/dev/peps/pep-0257/) of
a Python file, class, function, or method.  Examine the doctests in both files,
and the functions or methods to which they correspond.  Then complete the
following exercises to build a working forwarding table.  Read all exercises
before you begin, as it might be easier for you to do one before the other.


## Instructions

 1. Fill out the following functions (marked with `FIXME`) in `prefix.py`:

    - `ip_prefix_mask()`
    - `ip_prefix()`
    - `ip_prefix_total_addresses()`
    - `ip_prefix_nth_address()`
    - `ip_prefix_last_address()`

    These functions are short (approximately 1 - 2 lines of code) but require a
    bit of thought.

    A doctest is provided in the docstring of each of these functions, so you can
    see how they are called and what correct output looks.  Additionally, you
    can test functionality with the following command:

    ```
    python3 -m doctest prefix.py
    ```

    At this point, the following should run without error (and without output):
    ```
    python3 -m doctest prefix.py
    ```

 2. Fill out the method `Prefix.__contains__()`.

 3. Fill in the appropriate return value for each of the doctests for
    `Prefix.__contains__()` at the top of `prefix.py`.  `False` is currently
    used as a placeholder for each output, but the return value will be either
    `True` or `False`.

    - The return values in the doc tests must be correct; and
    - The following should run without error (and without output):
      ```
      python3 -m doctest prefix.py
      ```

 4. Fill out the following method (marked with `FIXME`):

    - `ForwardingTable.get_forwarding_entry()` (approx. 10 lines of code)

      Remember to use longest prefix match!

 5. Fill in the appropriate return value for each of the doctests for
    `ForwardingTable.get_forwarding_entry()` in `forwarding_table.py`.
    `('someintf', 'someip')` is currently used as a placeholder for each
    output, but the return value _should_ yield a tuple of type (`str`, `str`),
    corresponding to outgoing interface name and next hop-IP address (or
    `None`).

    Note that in the doctest, the next-hop IP address in every entry has
    a value other than `None`.  As you will see in the next part, there are
    instances when a next-hop value is `None`, in which case the destination
    IP address of the datagram being sent will be used as the next-hop IP
    address.

    When you have finished your revisions of `forwarding_table.py`:

    - The return values in the doc tests must be correct; and
    - The following should run without error (and without output):
    ```
    python3 -m doctest forwarding_table.py
    ```


# Part 3 - IP Forwarding

In this part of the lab, you will develop a working router implementation to
apply to your hosts and routers.


## Scenario Description

The file `scenario2.cfg` describes a network topology.  Hosts `a` and `b` are
connected to router `r1` via switch `s1`.  Hosts `c` through `k` are directly
connected to router `r1` on different interfaces.  Thus, `a` and `b` are on the
same LAN, together with `r1`'s `r1-s1` interface.  Hosts `c` through `k` are
each on their own LAN, shared only by the `r1` interface to which they are
connected.  Finally, hosts `l` and `m` are connected to router `r2` through
switch `s2`, and routers `r1` and `r2` are directly connected.

![scenario2.cfg](scenario2.png)

Again, the switches are already working; you do not have to implement switch
functionality.  Your focus is on the host/router functionality.


## Starter Commands

Take a look at the contents of `scenario2.cfg`.  Then run the following to
start it up:

```
$ cougarnet --disable-ipv6 scenario2.cfg
```

After a few seconds of awkward silence, you will see output on the terminal
corresponding to Host `a`.  The output is made by placeholder code in
`host.py`.  Instead of sending packets, it simply prints out that that's what
it would do.  What is missing at this point is:

 - logic to determine both
   - the interface out which the packet should be sent and
   - the contents (source and destination MAC address) of the Ethernet frame
     header that should encapsulate it;
 - some logic to determine which packets should be acted upon;
 - code to handle packets for which the receiving host is the final destination;
 - code to handle packets for which the receiving host is not the final
   destination.

These will be addressed by initializing the forwarding table you built in
[Part 2](#part-2---forwarding-table), looking up outgoing interface and next hop
in the forwarding table, and actually forwarding packets.  When these things
are added, you will be able to send IP packets from host to host, across
routers and multiple LANs.


## Packets Issued

With `scenario2.cfg`, `send_packet()` is called for the following packets at
the following times (note that times are approximate).  Refer to the
[network diagram above](#scenario-description-1) to help identify their route.
Each sub-bullet describes the purpose of the primary bullet under which it is
listed.

 - 4 seconds: packet sent from `a` to `b`.
   - `a` uses the IP destination as the next hop

 The next set of packets correspond to the tests in
 `forwarding_table.py` (see [Part 2](#part-2---forwarding-table)), so if your
 doctests work, then these should work.

 - 5 seconds: packet sent from `a` to `10.20.0.25`
 - 6 seconds: packet sent from `a` to `10.20.0.34`
 - 7 seconds: packet sent from `a` to `10.20.1.20`
 - 8 seconds: packet sent from `a` to `10.20.3.1`
 - 9 seconds: packet sent from `a` to `10.20.0.2`
 - 10 seconds: packet sent from `a` to `10.20.0.11`
 - 12 seconds: packet sent from `a` to `10.20.0.150`
 - 13 seconds: packet sent from `a` to `10.20.0.7`
 - 14 seconds: packet sent from `a` to `10.20.0.75`

 Finally:

 - 15 seconds: packet sent from `a` to `l`
   - A packet can be sent across several routers
 - 16 seconds: packet sent from `a` to `l` with TTL=1
   - A router drops packets whose TTL is 0 after decrementing


## Instructions

In the file `host.py`, flesh out following the skeleton methods related to IP
forwarding:

 - `__init__()`

   - Initialize the forwarding table (i.e., the one you created in Part 2)
     using two sources:

     - The entries from the `scenario2.cfg` configuration file, provided in the
       `COUGARNET_ROUTES` environment variable.  See the
       [documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#routes)
       for more on how to do this.  Each entry provided is a three-tuple
       consisting of prefix, outgoing interface, and next hop.

     - The IP prefixes associated with all the physical interfaces.  The IP
       prefix for an interface can be derived from the IP address and prefix
       length associated with that prefix.  The IP address and prefix length
       can be accessed via the `address` and `prefixlen` attributes of the IP
       address object returned by the `ipv4_address_info_single()` method
       (documented [here](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames)).
       With the IP address and prefix length in hand, you can use the
       `Host.prefix_for_int()` method to retrieve the prefix, which has been
       implemented for you.  Note that this method will only work if you have
       implemented the helper methods in `prefix.py` properly.

       For each interface, the forwarding entry you add should consist of the
       IP prefix for the interface, the name of the interface itself as the
       outgoing interface, and a next hop IP address of `None` (i.e., because
       it is on the same subnet).

     In both of these cases, call `ForwardingTable.add_entry()` to add the
     appropriate entries.  You can use the docstring at the top of the
     `forwarding_table.py` file as a guide for adding entries.

 - `send_packet()`.  This method takes the following as an argument:

   - `pkt`: an IP packet, complete with IP header.  Generally, this could be
     either an IPv4 or an IPv6 packet, but for the purposes of this lab, it
     will just be IPv4.

   The method should do the following:

   - Extract the destination IP address from the datagram.  Note that you do
     not need to parse the entire packet; you will do that in the next lab.

   - Find the matching entry in the host's forwarding table.  This yields a
     two-tuple corresponding to an outgoing interface and next hop IP address.

   - If the outgoing interface returned from the forwarding table lookup is
     `None`, then there is no matching route and thus no place to send the
     packet.  A full-functioning router would drop the packet and return an
     ICMP "network unreachable" packet to the sender.  But in this case, you
     can simply return from the function.

   - If the next hop returned from the forwarding table lookup is `None`, then
     use the destination IP address as the next hop.  This is the case for
     subnets to which the host is directly connected--i.e., the ones populated
     from the directly-connected prefixes above.

   - Call `send_packet_on_int()`, passing as arguments the IP datagram (`pkt`),
     the outgoing interface, and the next hop IP address.

 - `handle_ip()`.  This method takes the following as arguments:

   - `pkt` - the IP packet received
   - `intf` - the interface on which it was received

   This method is called by `_handle_frame()` when an IP frame is received, and
   the type field of the Ethernet frame header indicates that the Ethernet payload
   is an IPv4 packet (i.e., its type is `ETH_P_IP = 0x0800`).

   The method should do the following:

   - Extract the destination IP address from the packet.  Note that you do not
     need to parse the entire packet; you will do that in the next lab.

   - Determine if this host is the final destination for the packet, based on
     the destination IP address.  This host qualifies as the final destination
     if the following is true:

     - The destination IP address matches _any_ of the IP addresses on
       the host (i.e., not limited to the IP address on the incoming
       interface).  You can use the `ipv4_addresses()` method to find all IP
       addresses.

   - If the packet is destined for this host, based on the tests in the
     previous bullet, then call another method to handle the payload, depending
     on the protocol value in the IP header:

     - For type TCP (`IPPROTO_TCP = 6`), call `handle_tcp()`, passing the full
       IP datagram, including header.

     - For type UDP (`IPPROTO_UDP = 17`), call `handle_udp()`, passing the full
       IP datagram, including header.

     Note that if the protocol is something other than TCP or UDP, you can
     simply ignore it.

   - If the destination IP address does not match any IP address on the system, then call
     `not_my_packet()`, passing it the full IP datagram and the interface on
     which it arrived.

 - `forward_packet()`. This method takes the following as an argument:

   - `pkt` - the IP packet received

   The method should do the following:

   - Extract the time-to-live (TTL) value.  This value represents the number of
     remaining "hops" (i.e., routers) though which the packet can pass.

   - Decrement the TTL value by 1.  If the resulting value is 0, then simply
     return.  Expired packets should not be forwarded.

   - Replace the TTL in the IP datagram with the decremented value.  To do this
     you could simply extract everything before the TTL, extract everything
     after the TTL, and put the datagram back together by concatenating the
     first part, the TTL, and the last part. Again, you will parse the datagram
     more thoroughly in the next lab.

   - Extract the destination IP address from the packet.  Note that you do not
     need to parse the entire packet; you will do that in the next lab.

   - Call `send_packet()` on the modified packet.

 - `not_my_packet()`. This method takes the following as arguments:

   - `pkt` - the IP packet received
   - `intf` - the interface on which it was received

   The method should do the following:

   - If the value of the `_ip_forward` instance member is `False`, then there
     is no need to go any further!  Simply return;
   - Otherwise (`_ip_forward` is `True`), call `forward_packet()`.

 - `handle_tcp()`, `handle_udp()`.  There is no need to flesh out these
   methods.  They are placeholders for a future lab.  However, you can place
   debugging code in them, if you find it helpful.


## Testing

Test your implementation against scenario 2.  Determine the appropriate
output--that is, which hosts should receive which packets--and make sure that
the cougarnet output matches appropriately.

When it is working properly, test also with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario2.cfg
```


## Helps

### IPv4 Packets

Your code will need to parse IPv4 packets, both as received from the "wire" and
as passed by a method (e.g., `send_packet()`)--in both cases as `bytes`
instances.  The packet that you will be receiving looks like this:

<table border="1">
<tr>
<th>00</th><th>01</th><th>02</th><th>03</th><th>04</th><th>05</th><th>06</th><th>07</th>
<th>08</th><th>09</th><th>10</th><th>11</th><th>12</th><th>13</th><th>14</th><th>15</th>
<th>16</th><th>17</th><th>18</th><th>19</th><th>20</th><th>21</th><th>22</th><th>23</th>
<th>24</th><th>25</th><th>26</th><th>27</th><th>28</th><th>29</th><th>30</th><th>31</th></tr>
<tr>
<td colspan="4">Version</td>
<td colspan="4">IHL</td>
<td colspan="8">Differentiated Services</td>
<td colspan="16">Total length</td></tr>
<tr>
<td colspan="16">Identification</td>
<td colspan="3">Flags</td>
<td colspan="13">Fragment offset</td></tr>
<tr>
<td colspan="8">TTL</td>
<td colspan="8">Protocol</td>
<td colspan="16">Header checksum</td></tr>
<tr>
<td colspan="32">Source IP address</td></tr>
<tr>
<td colspan="32">Destination IP address</td></tr>
<tr>
<td colspan="32">Options and padding :::</td></tr>
</table>


### Address Representation Conversion

See the help on
[Address Representation Conversion](#address-representation-conversion) above.
above.


# Automated Testing

For your convenience, a [script](driver.py) is also provided for automated
testing of parts 1 and 3.  This is not a replacement for manual testing but can
be used as a sanity check.  You can use it by simply running the following in
the working directory:

```
./driver.py
```

Please note that if you have _only_ completed part 1, then the driver will
complain that `c` has not seen the ARP request from `r1` when running
scenario 1.  That's okay for part 1!  It's only important that `c` sees `r1`'s
ARP request (and the subsequent ICMP message) _after_ you implement
parts 2 and 3.


# Evaluation

Your score will be computed out of a maximum of 100 points based on the
following distribution:

 - Part 1: 40 points
 - Part 2: 32 points
   - 8 points for correct doctests in `prefix.py`
   - 8 points for running the following without error:
     ```
     $ python -m doctest prefix.py
     ```
   - 8 points for correct doctests in `forwarding_table.py`
   - 8 points for running the following without error:
     ```
     $ python -m doctest forwarding_table.py
     ```
 - Part 3: 28 points
   - 22 points for first 11 tests (2 points each)
   - 6 points for last test


# General Helps

 - Print to standard out for debugging purposes.  For a script running in a
   virtual host (i.e., with the `prog` option), all output will go to the
   terminal associated with that host, assuming `terminal=false` is not used in
   the configuration file and `--terminal=none` is not used on the command
   line.  See
   [the documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#additional-options).
   for more.
 - You can modify `scenario1.py`, `scenario2.py`, and the corresponding
   configuration files all you want for testing and for experimentation.  If
   this helps you, please do it!  Just note that your submission will be graded
   using only your `host.py`, `prefix.py`, and `forwarding_table.py`. The other
   files used will be the stock files [you were provided](#resources-provided).
 - Save your work often, especially as you move from part to part.  You are
   encouraged to
   [commit your changes](../01b-hw-github-repo-mirror/README.md#commit-and-push-local-changes-to-private-repo).
   to the private GitHub repository that you created
   [in an earlier assignment](../01b-hw-github-repo-mirror/README.md).
   Please ensure that it remains private!


# Looking Ahead (Optional)

The [final lab](../13-lab-full-stack-network/) for this class will put
together all the network components implemented in the previous labs, including
this lab.  This section helps you add some of the components that are not
required for the current lab but that you will need for the final lab.  You are
not required to implement them now, but if you want to be more prepared for the
final lab, you might find it advantageous to do so.


## Add Switch

To integrate the switch that you implemented in the previous lab, copy your
working `switch.py` from the
[Link Layer Lab](../04-lab-link-layer/) into your current directory.  Then run
the following:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1-mine.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario2-mine.cfg
```

Yep, that is all your software moving around real frames and packets!


## Handle IP Broadcasts

(Will be added soon...)


# Submission

Use the following commands to create a directory, place your working files in
it, and tar it up:

```
$ mkdir network-lab
$ cp host.py prefix.py forwarding_table.py network-lab
$ tar -zcvf network-lab.tar.gz network-lab
```
