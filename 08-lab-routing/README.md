# Routing Lab

The objective of this assignment is to give you experience with how routing
protocols work.  To accomplish this, you will implement the a basic distance
vector (DV) routing protocol and populate a router's forwarding tables using
the routes learned.

 - [Getting Started](#getting-started)
   - [Maintain Your Repository](#maintain-your-repository)
   - [Update Cougarnet](#update-cougarnet)
   - [Install Dependencies](#install-dependencies)
   - [Modify Virtual Machine Resources](#modify-virtual-machine-resources)
   - [Resources Provided](#resources-provided)
   - [Starter Commands](#starter-commands)
   - [Scenario Descriptions](#scenario-descriptions)
   - [Packets Issued](#packets-issued)
 - [Instructions](#instructions)
   - [Copy `prefix.py`](#copy-prefixpy)
   - [Specification](#specification)
   - [Scaffold Code](#scaffold-code)
   - [Testing](#testing)
 - [Automated Testing](#automated-testing)
 - [Evaluation](#evaluation)
 - [Helps](#helps)
   - [Useful Methods](#useful-methods)
   - [Other Helps](#other-helps)
 - [Automated Testing](#automated-testing)
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


## Install Dependencies

Install [pyroute2](https://pyroute2.org/) by running the following:

```
$ sudo apt install python3-pyroute2
```


## Modify Virtual Machine Resources

This lab requires your VM to start 15 virtual hosts (scenario 3).  For some
host systems, this can be quite intense.  To help address this, it might be
beneficial to shut down your VM and use VirtualBox or UTM to increase the
number of cores associated with your VM.


## Resources Provided

The files given to you for this lab are the following:
 - `dvrouter.py` - a file containing a stub implementation of a host (and
   router).  This is where you will do your work!

   Note that in this lab, your focus is not forwarding but rather routing.
   Thus, virtual hosts will not use the functionality in your `Host` class for
   forwarding but will instead use the native network stack of the virtual
   host.

   Nonetheless, with just a bit of effort, you _could_ drop in your `host.py`
   from the
   [Network-Layer Lab](../06-lab-network-layer/),
   and have `DVRouter` inherit from that instead of from `BaseFrameHandler`.
   Then, if you
   [configure the host](https://github.com/cdeccio/cougarnet/blob/main/README.md#network-configuration-file)
   to use `native_apps=no`, you are using your own
   implementation for sending Ethernet frames, ARP, IP forwarding, and
   routing!
 - `prefix.py` - This blank file will be
   [replaced](#copy-prefixpy) with the `prefix.py` you created in the
   [Network-Layer Lab](../06-lab-network-layer/).  It is placed here only to allow
   the [starter commands](#starter-commands) to run without error.
 - `scenario1.cfg`, `scenario2.cfg`, and `scenario3.cfg` -
   [network configuration files](https://github.com/cdeccio/cougarnet/blob/main/README.md#network-configuration-file)
   describing three topologies for testing your routing implementation.
 - `scenario1.py`, `scenario2.py`, and `scenario3.py` -
   scripts that run various tests in conjunction with the network configuration
   files.
 - `scenario1a.cfg` - a variant of `scenario1.cfg`, in which no script is
   called, but you can simply look at the toplogy and the forwarding tables in
   their initial state.


## Starter Commands

Take a look at the contents of `scenario1a.cfg`.  Then run the following to
start it up:

```
$ cougarnet --display --disable-ipv6 scenario1a.cfg
```

The `--disable-ipv6` option is used on the command line here and throughout the
remainder of the lab to prevent your forwarding tables from being populated
with IPv6 prefixes, so you can focus exlusively on routing with a single
protocol.

You will notice that, by default, terminal windows appear for every host.  You
can disable this with the `--terminal=none` option or by specifying
`terminal=false` in the configuration file.

Run the following commands on host `r2` to show its network interface
configuration and forwarding table:

```bash
r2$ ip addr 2> /dev/null
r2$ ip route
```

(The `2> /dev/null` simply redirects standard error, which is noisy due to
unknown causes related to working in a private network namespace :))

You should only see two entries in the forwarding table:

```
10.0.0.0/30 dev r2-r1
10.0.0.4/30 dev r2-r3
```

Each entry corresponds to an interface on the router.  These table entries are
created automatically by the system when the interfaces are configured with
their respective IP addresses and prefix lengths.  So basically at this point,
`r2` knows that to get to the subnet corresponding to its `r2-r1` interface, it
sends a packet out `r2-r1`, and to get to the subnet corresponding to its
`r2-r3` interface, it sends a packet out `r2-r3`.  (Note that these entries are
exactly what you integrated into your router code in the `__init__()` method of
your `Host` code as part of the
[network-layer lab](../06-lab-network-layer/README.md#instructions)!)
The problem is that for any destinations outside of these local subnets, it
doesn't know where to go!

Rather than manually adding static forwarding entries, like you did with the
previous [homework](../05-hw-network-layer/) and [lab](../06-lab-network-layer/),
in this lab, you will update the forwarding tables dynamically using a distance
vector (DV) protocol.  Indeed, you will have a working router that will not
only be capable of _forwarding_ packets but also _routing_!

Note that the _forwarding_ function is handled using the native Linux network
stack; you do not have to implement its functionality!  Your focus is on
_routing_.  Thus, your DV protocol will be updating the actual forwarding table
on each router / virtual host.

Now look at the contents of `scenario1.cfg`, and run the following to start it
up:

```
$ cougarnet --disable-ipv6 scenario1.cfg
```

On the terminal from which you started Cougarnet, you will see log messages
indicating that ICMP packets are being sent and links being dropped as
[specified](#packets-issued).  On the terminal corresponding to each router,
you will simply see a notice every second that a DV table is being sent.  This
is simply a notice that the `send_dv()` method is being called. You will be
fleshing out that method, and others, such that the ICMP packets sent are seen
by multiple routers, including the destination.


## Scenario Descriptions

Your working router should work in the following three scenarios, described in
the files `scenario1.cfg`, `scenario2.cfg`, and `scenario3.cfg`, respectively.


### Scenario 1

In scenario, routers `r1` through `r5` are connected in a line.

```
  r1 --- r2 --- r3 --- r4 --- r5
```


### Scenario 2

In scenario, routers `r1` through `r6` are connected in a ring.

```
    r1 --- r2
   /         \
  /           \
 r6            r3
  \           /
   \         /
    r5 --- r4
```

After some time, the link between `r1` and `r6` is dropped:

```
    r1 --- r2
  XX         \
              \
 r6            r3
  \           /
   \         /
    r5 --- r4
```

### Scenario 3

In scenario, routers `r1` through `r15` are connected in a more complex
topology.

```
       --- r7 ----r8
      /    |      |
     /     |      |
   r9      |      |
     \     |      |
      \    |      |
       --- r6     r2 --- r14 --- r15
            \    /  \    /
             \  /    \  /
      r11 --- r1      r3
              |       |
              |       |
              r4 ---- r5 --- r13
              |       |
              |       |
             r10     r12
```

After some time, the link between `r2` and `r8` is dropped:

```
       --- r7 ----r8
      /    |
     /     |      |
   r9      |     XXX
     \     |      |
      \    |
       --- r6     r2 --- r14 --- r15
            \    /  \    /
             \  /    \  /
      r11 --- r1      r3
              |       |
              |       |
              r4 ---- r5 --- r13
              |       |
              |       |
             r10     r12
```


## Packets Issued

ICMP packets are sent using `ping` in each scenario.  In each case, the point
of this call to `ping` is to check that:

 - there is a path (i.e., forwarding entries in routers along the way) from the
   source (i.e., the host on which `ping` is executed) and the destination
   (i.e., the destination argument specified on the command line);
 - there is a return path from the (original) destination to the (original)
   source;
 - the path from source to destination and back again is the shortest path.

In each scenario the first set of ICMP packets will be issued after routes will
have propagated, distance vectors converged, and forwarding tables have the
proper entries for shortest-path forwarding.  For scenarios 2 and 3 a second
set of ICMP packets will be issued after a given link has been dropped and the
distance vectors and forwarding table entries have been updated properly.


### Scenario 1

 - 4 seconds: ICMP packet sent from `r1` to `r5` and back again
 - 5 seconds: ICMP packet sent from `r2` to `r4` and back again


### Scenario 2

 - 4 seconds: ICMP packet sent from `r2` to `r6` and back again
 - 5 seconds: ICMP packet sent from `r2` to `r4` and back again
 - 6 seconds: Link dropped between `r1` and `r6`
 - 12 seconds: ICMP packet sent from `r2` to `r6` and back again
 - 13 seconds: ICMP packet sent from `r2` to `r4` and back again


### Scenario 3

 - 4 seconds: ICMP packet sent from `r9` to `r10` and back again
 - 5 seconds: ICMP packet sent from `r9` to `r11` and back again
 - 6 seconds: ICMP packet sent from `r9` to `r12` and back again
 - 7 seconds: ICMP packet sent from `r9` to `r13` and back again
 - 8 seconds: ICMP packet sent from `r6` to `r14` and back again
 - 9 seconds: ICMP packet sent from `r7` to `r15` and back again
 - 10 seconds: Link dropped between `r2` and `r8`
 - 18 seconds: ICMP packet sent from `r7` to `r15` and back again


# Instructions

Read Section 5.2.2 ("The Distance-Vector (DV) Routing Algorithm") in the book.
Then implement a DV router in `dvrouter.py` with the following functionality.


## Copy `prefix.py`

Copy your fleshed out copy of `prefix.py` from the
[previous lab](../06-lab-network-layer/README.md#part-2---forwarding-table):

```bash
$ cp ../06-lab-network-layer/prefix.py .
```

While not everything needs to be working, the IP manipulation functions do need
to work properly, enough to allow the `ip_prefix_last_address()` function to
work properly.


## Specification

 - A router starts out knowing only about the IP prefixes to which it is
   directly connected.  For example, as shown in the
   [example given previously](#starter-commands), `r2`'s initial DV in
   scenario 1 (i.e., before it receives any DVs from neighbors) from the would
   look something like this:

   - Prefix: 10.0.0.0/30; Distance: 0
   - Prefix: 10.0.0.4/30; Distance: 0

   However, we will _not_ do that for for this lab.  Instead, the prefixes that
   will be passed around will be /32's.  That is, we will treat IP _addresses_ as
   the IP _prefixes_.  Thus, instead of `r2` starting with `10.0.0.0/30` and
   `10.0.0.4/30`, it will start with:

   - Prefix: 10.0.0.2/32; Distance: 0
   - Prefix: 10.0.0.5/32; Distance: 0

   The short explanation for this is that it will simplify things, so you can
   focus on the routing.

   Here is the longer explanation.  You might notice that when we advertise the
   entire prefix, instead of the /30, both `r1` and `r2` (in scenario 1) will
   have an entry for `10.0.0.0/30`.  You might ask when how a packet leaving
   `r5` to 10.0.0.1 (`r1`) will actually reach `r1`, seeing as `r2` is
   indicating that it can reach `10.0.0.0/30` with distance 0.  The answer is that
   once such a packet reaches `r2`, `r2` discovers (from its IP forwarding
   table) that the packet's final destination is on the subnet associated with
   its `r2-r1` interface.  So it just needs to craft a special Ethernet frame
   using the MAC address of the final destination (in this case 10.0.0.1 or
   `r1`'s `r1-r2` interface).  How does it know that MAC address?  From ARP, of
   course :).  In _this_ lab, by routing with /32 prefixes, we remove the
   dependency on ARP to keep things more simple.

   The IP address for each interface can be found by calling the
   `ipv4_address_info_single()` method.  To make it a prefix, simply add "/32"
   to the end.

 - A router sends its own DV to every one of its neighbors in a UDP datagram.
   You do not have to set up the socket for sending and receiving UDP datagrams
   containing DV messages.  This has been done for you.  When you have the payload
   ready, you can simply call `self._send_msg()`, which takes the following as
   arguments:

   - `msg` - a `bytes` instance containing the DV message.  This will be sent
     as a UDP payload.  You do not need to create any headers for this; they
     will be created for you as part of normal socket functionality.
   - `dst` - a `str` instance containing the IP address to which the message
     should be sent.

   Sending a DV message to every neighbor means sending a DV message out every
   interface.  Since this is a discovery process, you don't actually know the
   IP address of your neighbor, so you cannot use that for your destination
   address, `dst`.  Instead, for a given interface, you will send to the IP
   address that is the _broadcast_ address corresponding to the subnet on the
   interface.  The broadcast address for a given subnet is simply the subnet
   prefix with all of the host bits set--or, the very last address in the
   subnet.  For example, the broadcast address for 10.1.2.0/24 is 10.1.2.255.
   And the broadcast address for 10.1.2.20/30 is 10.1.2.23.
   
   You might recall that the [previous lab](../06-lab-network-layer/) had you
   create several functions related to IP prefix handling, one of which was to
   generate the broadcast (last) address for a given subnet (see
   [Part 2](../06-lab-network-layer/README.md#part-2---forwarding-table) and also
   the `handle_ip()` method in
   [Part 3](../06-lab-network-layer/README.md#instructions-2).  The
   `bcast_for_int()` method uses those functions to return the broadcast IP
   address for the subnet associated with a given interface.

   Note that the subnet-specific broadcast address is used instead of a global
   broadcast (255.255.255.255) for (at least) two reasons:

   - Since our packet only needs to reach the other side of the link, to a
     neighbor that we know has an IP address on the same subnet, there is no
     reason to use a more general broadcast address with which the packet could
     potentially get forwarded beyond the subnet/link/local area network (LAN).
     Using this address will guarantee that.
   - Sending a packet with 255.255.255.255 requires root privileges.  We know
     how to do this, but the principle of least privilege indicates that we
     should only elevate when necessary.

 - Each DV message has the following properties:

   - the source IP address corresponding to the interface out from which the
     packet is being sent. This can be found with the
     `ipv4_address_info_single()` method, which is documented
     [here](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames).
   - the name of the router sending the message.  This is can be found with the
     `hostname` attribute, which is initialized for you in `__init__()`.
   - the distance vector of the sending router.

   These properties can be put together however you want, but it is recommended
   that you create a `dict` object that you can convert to a `str` (and
   eventually to `bytes`) using JSON.  For example:

   ```python
   obj = { 'ip': '10.0.0.1', 'name': 'r2', 'dv': { '10.0.0.2/32': 0, '10.0.0.5': 0 } }
   obj_str = json.dumps(obj)
   obj_bytes = obj_str.encode('utf-8')
   ```

 - When a router receives a DV message from one of its neighbors, it does the following:

   - Converts the message to a `str` (from `bytes`) and decodes the JSON using
     something like the following:

     ```python
     obj_str = msg.decode('utf-8')
     obj = json.loads(obj_str)
     ```

   - Extracts the name, IP address, and DV of the neighboring node.
   - Discards the packet if it is one of its own packets (i.e., the
     `self.hostname` matches the name of the router in the DV message).
     Because the destination IP address is the (subnet) broadcast address, the
     sending router might actually receive its own message.
   - Maps the neighbor's name to its IP address.  This will make things a lot
     easier when creating forwarding table entries.
   - Saves the neighbor's DV, replacing any previous version, so it can be used
     later for running Bellman-Ford algorithm.

 - A router creates its own DV using the Bellman-Ford algorithm.  By iterating
   through the DV of every neighbor, a router learns the shortest distance to
   every prefix known by its collective neighbors.  _Eventually_ (after
   several iterations), it will converge, such that its DV contains the
   shortest distances to each IP prefix.  Bellman-Ford requires comparing the
   the sum of 1) the cost of the link for a given neighbor and 2) that
   neighbor's distance (according to its DV), for all neighbors.  The distance
   from each neighbor to a destination is contained in the neighbors' DVs.  The
   cost to each neighbor, for the purposes of this lab, is simply 1.

   To a newly-created DV, a router adds entries for each local prefix (IP
   address), just as it did when the DV was initially created.  Just as before,
   those prefixes will always have a distance of of zero.

 - A router distributes its DV to its neighbors every second. This both
   provides an update to neighbors and serves as a keep-alive, to let neighbors
   know that the link is still up.

 - A router updates its forwarding table whenever its own DV has changed after
   its re-creation.  For every prefix in its DV, the next hop is the IP address
   of the neighbor resulting from an incoming neighbor DV message).  A
   forwarding table entry for a prefix consists of the IP address of the
   neighbor having the lowest distance to that prefix as the next-hop IP
   address.  The `add_entry()` method of the forwarding table instance will
   allow you to pass `None` as the interface, and it can be inferred from the
   next hop (this is made possible because of the local forwarding table
   entries, which are created by default, as described
   [previously](#starter-commands)).

   *IMPORTANT*: Only update your forwarding table when your DV has *changed*
   after an update!!

   There are two primary ways to update the forwarding table:

   - Call the `flush()` method on the forwarding table instance to clear out
     all existing entries, and then build the table from scratch; or
   - Call the `get_all_entries()` method on the forwarding table instance to
     get its current state, and then add/remove using the `add_entry()` and
     `remove_entry()` methods, respectively, to update the table.

   If the prefix is one that is local to this host (i.e., distance is 0), your
   code does not need to create forwarding entry--because the host *is* the
   final destination (i.e., it doesn't need to be forwarded)!

 - A router keeps track of the last time that it received a DV message from
   every neighbor.  After three seconds have passed since receiving a DV
   message from a neighbor, the router discards that neighbor's DV, such that
   it and its prefixes are no longer considered in the computation of the
   router's own DV table (and forwarding table).


## Scaffold Code

In the file `dvrouter.py`, flesh out following the skeleton methods to help you
implement the above specification.

 - `handle_dv_message()`.  This method is called by `_handle_msg()`, which
   receives a UDP message from a UDP socket.  It takes the following as an
   argument:

   - `msg`: a DV message (`bytes`), consisting of JSON representing the DV of
     the neighbor that sent it.

   The method should do everything that is associated with receiving a DV
   message.

 - `update_dv()`.  This method takes no arguments.  The method is called by
   `update_dv_next()` (implemented for you) every 1 second.  It should
   implement the Bellman-Ford algorithm, yielding a newly-created DV for the
   router.  In the case that the DV changes, the IP addresses of the neighbors
   with shortest distances to IP prefixes are used to create new forwarding table
   entries.

 - `send_dv()`.  This method takes no arguments.  The method is called by
   `send_dv_next()` (implemented for you) every 1 second.  With it, a router
   sends its own DV to each of its neighbors.

 - `handle_down_link()`.  This method takes a single argument:

   - `neighbor`: the hostname (`str`) of the neighbor corresponding to the link
     that is no longer up.

   The method should be called whenever a router has detected a down link
   (through lack of keep-alive DV messages).  Basically this method should
   simply discard the DV of the neighbor whose link is down.

Please note that `send_dv()` is automatically called every second, at 1
second, 2 seconds, etc.  This is done _for you_ with the initial call to
`send_dv_next()` (at 1 second), which perpetually calls `send_dv()` and then
schedules `send_dv_next()` again one second later. Similarly, `update_dv()` is
automatically called every second, at 0.5 seconds, 1.5 seconds, etc.  This is
also done for you with the initial call to `update_dv_next()` (at 0.5 seconds),
which perpetually calls `update_dv()` and then schedules `update_dv_next()`
again one second later.

You should not call `send_dv()` or `update_dv()` anywhere else in your code.


## Testing

Test your implementation against scenario 1:

```
$ cougarnet --disable-ipv6 --stop=30 scenario1.cfg
```

Determine the appropriate output--that is, which hosts should see the scheduled
ICMP packets on their way and back--and make sure that the cougarnet output
matches appropriately.

The `--stop=30` option is used to make sure that the Cougarnet instance running
your scenario terminates if 30 seconds have passed.  You can adjust this number
however you'd like.  However, I do recommend using the `--stop` option for this
lab. If your router code gets into a loop that is otherwise difficult to
interrupt, the `--stop` argument will help get it under control.

When it is working properly, test also with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1.cfg
```

Then proceed to test scenarios 2 and 3.

```
$ cougarnet --disable-ipv6 --stop=30 scenario2.cfg
$ cougarnet --disable-ipv6 --stop=50 scenario3.cfg
```

When all are working properly, test also with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario2.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario3.cfg
```


# Automated Testing

For your convenience, a [script](driver.py) is also provided for automated
testing.  This is not a replacement for manual testing but can be used as a
sanity check.  You can use it by simply running the following in the working
directory:

```
./driver.py
```


# Evaluation

Your score will be computed out of a maximum of 100 points based on the
following distribution:

 - Scenario 1: 40 points
 - Scenario 2: 30 points
 - Scenario 3: 30 points


# Helps

## Useful Methods

 - The `ForwardingTableNative.get_all_entries()` will return all entries
   currently in the forwarding table.  You can use this along the way to
   inspect the current state of your table.  By default the prefix and next
   hop are IP addresses.  However, if you pass `resolve=False` into
   `get_all_entries()`, it replaces those addresses with hostnames, which might
   help your troubleshooting.
 - Similarly, the `DVRouter.resolve_dv()` method takes as an argument a DV
   (`dict`) and replaces the IP address (key) with the corresponding hostname.

## Other Helps

 - Get the routing code working first, then focus on recovery after a dropped
   link is detected.
 - In `update_dv()`, do _not_ try to optimize by _updating_ your DV.  Re-create
   your DV every time, using the 1) initial (local) prefixes and 2) the
   prefixes learned from neighbors' DVs.
 - Your down link detection might be implemented in several ways.  One way is
   to use the scheduler documented
   [here](https://github.com/cdeccio/cougarnet/blob/main/README.md#networkeventloop),
   creating an event for a given neighbor that calls `handle_down_link()` after
   the specified time has passed and cancelling/re-creating the event every
   time a message was received from that neighbor.
 - Print to standard out for debugging purposes.  For a script running in a
   virtual host (i.e., with the `prog` option), all output will go to the
   terminal associated with that host, assuming `terminal=false` is not used in
   the configuration file and `--terminal=none` is not used on the command
   line.  See
   [the documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#additional-options).
   for more.
 - You can modify `scenario1.py`, `scenario2.py`, `scenario3.py`, and the
   corresponding configuration files all you want for testing and for
   experimentation.  If this helps you, please do it!  Just note that your
   submission will be graded using only your `dvrouter.py`. The other files
   used will be the stock files
   [you were provided](#resources-provided).
 - Save your work often.  You are welcome (and encouraged) to use a version
   control repository, such as GitHub.  However, please ensure that it is a
   private repository!


# Automated Testing

(Driver is work-in-progress and will be included soon.)

For your convenience, a [script](driver.py) is also provided for automated
testing.  This is not a replacement for manual testing but can be used as a
sanity check.  You can use it by simply running the following in the working
directory:

```
./driver.py
```


# Submission

Upload your functional `dvrouter.py` to the assignment page on LearningSuite.
