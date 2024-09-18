# Link-Layer Lab

The objective of this assignment is to give you hands-on experience with the
link layer, local area networks (LANs), switching, and virtual LANs (VLANs), by
implementing a link-layer switch!


# Table of Contents

 - [Getting Started](#getting-started)
   - [Maintain Your Repository](#maintain-your-repository)
   - [Update Cougarnet](#update-cougarnet)
   - [Resources Provided](#resources-provided)
   - [Starter Commands](#starter-commands)
   - [Scenario Descriptions](#scenario-descriptions)
   - [Frames Issued](#frames-issued)
 - [Instructions](#instructions)
   - [Part 1 - Link-Layer Forwarding and Learning](#part-1---link-layer-forwarding-and-learning)
   - [Part 2 - VLANs and Trunking](#part-2---vlans-and-trunking)
 - [Automated Testing](#automated-testing)
 - [Evaluation](#evaluation)
 - [Helps](#helps)
   - [Ethernet Frames](#ethernet-frames)
   - [Working with `bytes` Instances](#working-with-bytes-instances)
   - [Sending and Receiving Frames](#sending-and-receiving-frames)
   - [Other Helps](#other-helps)
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
 - `switch.py` - a file containing a stub implementation of a switch. This is
   where you will do your work!
 - `host.py` - a script that will be run on every host.  It does two things:
   - [Sends a log message to the calling process](https://github.com/cdeccio/cougarnet/blob/main/README.md#communicating-with-the-calling-process)
     every time a frame is received.  This message will be printed out to the
     terminal on which the calling process is running.
   - Sends frames to other hosts on the network at certain times relative to
     the start of the simulation, depending on the name of the host on which it
     is running.
 - `scenario1.cfg`, `scenario2.cfg`, `scenario3.cfg` -
   [network configuration files](https://github.com/cdeccio/cougarnet/blob/main/README.md#network-configuration-file)
   describing three link-layer topologies.
 - `scenario1a.cfg` - a variant of `scenario1.cfg`, designed to show how things
   might operate with a real switch--with some caveats.


## Starter Commands

Take a look at the contents of `scenario1a.cfg`.  Then run the following to
start it up:

```
$ cougarnet --display --disable-ipv6 scenario1a.cfg
```

The `--disable-ipv6` option is used on the command line here and throughout the
remainder of the lab to prevent some noise specific with IPv6 from cluttering up
our link-layer study.

You will notice that, by default, terminal windows appear for every host and
for the switch.  Also, all terminals, except the one for the switch, are
running a program, `host.py`, which you will find in the local directory. The
program to be run for each host is specified the configuration file,
`scenario1a.cfg`, using the `prog` attribute. (See the
[Cougarnet documentation](https://github.com/cdeccio/cougarnet#running-programs)
for more.) You can modify which hosts have terminals--or disable them
completely--with the `--terminal` option.

Now take a look at the terminal from which you ran `cougarnet`.  After several
seconds, you will see log messages from different hosts, indicating that
Ethernet frames have been received.  These messages come from the following
code in `host.py`:

```python
def _handle_frame(self, frame, intf):
    frame = Ether(frame)
    self.log(f'Received frame on %7s: {frame.src} -> {frame.dst}' % intf)
```

The method `_handle_frame()` is called every time a frame is received by the
host running `host.py`.  The contents of the frame are stored as a Python
`bytes` object in the `frame` parameter, and the network interface on which the
frame was received is stored as a Python `str` object in the `intf` parameter.
The incoming interface (`intf`) as well as source (`frame.src`) and destination
(`frame.dst`) MAC addresses of the received frame are logged using
`self.log()`, which results in the printouts on the terminal from which
`cougarnet` was run.

Note that a `scapy.layers.l2.Ether` object is instantiated to facilitate
parsing of the Ethernet frame.  scapy is used in scripts for future labs as
well. However, you will not be allowed to use scapy in your own code; parsing
frames (and later packets) is part of the learning activities.

Now look at the contents of `scenario1.cfg`, and run the following to start it
up:

```
$ cougarnet --display --disable-ipv6 scenario1.cfg
```

It is similar in some senses, but very different in some others.  Note the
following:

 - The terminal from which you called `cougarnet` has no output.
 - The switch is printing (to standard output) strange-looking strings.

What is going on?  Well, there is no switch functionality written in
`switch.py`; the script is simply printing out the representation of the frames
that it is seeing on its interfaces.  You can see this in `switch.py`:

```python
def _handle_frame(self, frame, intf):
    print('Received frame: %s' % repr(frame))
```

Your job, of course, is to modify the behavior of `_handle_frame()` in
`switch.py`, so that the appropriate hosts actually receive the frames, similar
to what you observed when running the config file `scenario1a.cfg`.  (Please
note, however, that `scenario1a.cfg` is not a complete solution.) This will
result in the log messages that are expected at the terminal running
`cougarnet`.  That is, you will create a working link-layer switch!


## Scenario Descriptions

Your working switch should work in the following three scenarios, described in
the files `scenario1.cfg`, `scenario2.cfg`, and `scenario3.cfg`, respectively.


### Scenario 1

Scenario 1 is a simple scenario in which hosts `a`, `b`, `c`, `d`, and `e` are
all connected to a single switch, `s1`.  There are no VLANs or trunking.
```
          +---+
          | a |
          +---+
            |
            |
            |
+---+     +--------+
| c | --- |        |
+---+     |   s1   |
+---+     |        |
| d | --- |        |
+---+     +--------+
            |    |
            |    |
            |    |
          +---++---+
          | e || b |
          +---++---+
```


### Scenario 2

In scenario 2 hosts `a` and `b` are connected to switch `s1`, hosts `c`, `d`,
and `e` are connected to switch `s2`, and hosts `s1` and `s2` are connected to
each another.  There are no VLANs or trunking.
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
+---+     +----+     +---+
| d | --- | s2 | --- | e |
+---+     +----+     +---+
            |
            |
            |
          +----+
          | c  |
          +----+
```


### Scenario 3

In scenario 3 hosts `a` and `b` are connected to switch `s1`, hosts `c`, `d`,
and `e` are connected to switch `s2`, and hosts `s1` and `s2` are connected to
each another.  Hosts `a`, `c`, and `e` are on VLAN 10, and hosts `b` and `d`
are on VLAN 20.  The connection between switches `s1` and `s2` is a trunk.
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
+---+     +----+     +---+
| d | --- | s2 | --- | e |
+---+     +----+     +---+
            |
            |
            |
          +----+
          | c  |
          +----+
```


## Frames Issued

In every scenario, the following frames are sent at the following times (note
that times are approximate).  Each sub-bullet describes the purpose of the primary
bullet under which it is listed.  That is, it describes what is being tested.

 - 4 seconds: frame sent from `a` to `c`
   - There is no table entry for any host, and `c` in particular
 - 5 seconds: frame sent from `c` to `a`
   - There is a table entry for `a`
 - 6 seconds: frame sent from `a` to `c`
   - There is a table entry for `c`
 - 7 seconds: frame sent from `a` to broadcast
   - Broadcast is always sent to all interfaces on the LAN or VLAN (except the interface from which it came)
 - 8 seconds: frame sent from `e` to `a`
   - Establish a table entry for `e` -- in preparation for future tests
 - 9 seconds: frame sent from `a` to `e`
   - There is a table entry for `e`
 - 10 seconds: frame sent "from" `e` (spoofed from `c`'s port) to `a`
   - Update the table entry for `e` -- in preparation for future tests
 - 11 seconds: frame sent from `a` to `e`
   - The table entry for `e` has been updated
 - 14 seconds: frame sent from `e` to `a`
   - The table entry for `a` has not expired
 - 15 seconds: frame sent from `a` to `c`
   - The table entry for `c` has expired


# Instructions

## Part 1 - Link-Layer Forwarding and Learning

Read Section 6.4.3 ("Link-Layer Switches") in the book, especially the
sub-sections "Forwarding and Filtering" and "Self-Learning", and especially
pages 492 and 493.

Then implement a basic switch in `switch.py` with the following functionality:

 - The switch has a MAC address table mapping MAC addresses to interfaces.
 - The MAC address table is initialized as an empty mapping.
 - A new table entry is added or an existing entry updated with every incoming
   frame.
 - The aging time of a new table entry is 8 seconds.  When a frame arrives
   corresponding to an existing entry, its aging time is reset to 8 seconds.
 - Table entries are purged as their aging time expires.
 - A non-broadcast frame is forwarded as-is (unchanged) to the interface
   corresponding to the table entry of the destination MAC address, if such an
   entry exists; if no entry exists, then it is forwarded to every interface,
   except that from which it originated.
 - A broadcast frame (i.e., having destination MAC address `ff:ff:ff:ff:ff:ff`)
   is forwarded as-is to all interfaces, except that from which it originated.

Note that it might be easiest to start with basic switch functionality, then
implement the aging time.  See the [Help](#helps) section for an
[Ethernet frame reference](#ethernet-frames), as well as implementation tips
and examples.

Test your implementation against scenarios 1 and 2.  Determine the appropriate
output--that is, which hosts should receive which frames--and make sure that
the output for your switch implementation matches appropriately.

When it is working properly, test also with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario2.cfg
```

You can also use the driver provided for
[automated testing](#automated-testing).

Now would be a good time to
[save your work](../01b-hw-github-repo-mirror/README.md#commit-and-push-local-changes-to-private-repo).


## Part 2 - VLANs and Trunking

Read Section 6.4.4 ("Virtual Local Area Networks (VLANs)") in the book.

Now add implementation for VLANs and trunking according to the following:

 - A frame should only ever be forwarded to interfaces that share the same VLAN
   as the interface from which it originated, or to a trunk interface.  This is
   true whether a table entry exists for a given MAC address, no entry exists,
   or the destination MAC address of the frame is the broadcast address.
 - When a frame is sent to a trunk port, it should be converted to an 802.1Q
   frame, such that the frame header includes the VLAN ID, in addition to the
   rest of the frame header, and the original payload.
 - When a frame is received on a trunk port, it should be converted from an
   802.1Q frame to a vanilla Ethernet frame.  The VLAN ID should be extracted,
   and used to determine the interface(s) (if any) to which the frame should be
   forwarded.

Note that when a switch is initialized, it is populated with information about
each interface, including the VLAN it is associated with.  You can retrieve a
list of objects containing information for all "physical" interfaces on the
system with the `physical_interfaces_info()` method of your Switch instance
(inherited from the `BaseHost` class).  You can access the MAC address and
interface name associated with each interface by accessing using
dictionary-like syntax on the object: `myobj['address']` and `myobj['ifname']`.
You can use the `int_to_vlan` attribute to map an interface name to the
VLAN for that interface, and the `is_trunk_link()` method will identify a trunk
link. More information can be found in the
[documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames).

See the [Help](#helps) section for more, including an
[802.1Q frame reference](#ethernet-frames), and implementation tips and
examples.

Test your implementation against scenario 3.  Determine the appropriate
output--that is, which hosts should receive which frames--and make sure that
the output for your switch implementation matches appropriately.

Even though it wasn't obvious, the switches in scenario1.cfg and scenario2.cfg
were configured with VLANs.  It just so happens that when VLANs are not
_explicitly_ configured for a switch (i.e., in the configuration file), _every_
interface on that switch is _implicitly_ assigned to VLAN 0. What this means
for you is that the code you write to handle scenario 3 should still handle
scenarios 1 and 2, without having to make any special provisions.

When your switch implementation is working properly, test all three scenarios
with the `--terminal=none` option:

```
$ cougarnet --disable-ipv6 --terminal=none scenario1.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario2.cfg
$ cougarnet --disable-ipv6 --terminal=none scenario3.cfg
```

You can also use the driver provided for
[automated testing](#automated-testing).


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

 - Part 1: 60 points
   - 30 points for scenario 1
   - 30 points for scenario 2
 - Part 2: 40 points


# Helps


## Ethernet Frames

Your code will need to parse Ethernet frames from the "wire" as `bytes`
instances.  The frame that you will be receiving looks like this:

| Destination MAC Addr | Source MAC Addr | EtherType | Payload |
| :---: | :---: | :---: | :---: |
| (48 bits) | (48 bits) | (16 bits) | (variable) |

Note that a complete Ethernet frame also has fields for preamble and Cyclic
Redundancy Check (CRC) when it actually travels on the wire.  However, these
frames are read from a raw socket (i.e., of type `SOCK_RAW`, as opposed to
`SOCK_STREAM` or `SOCK_DGRAM`), and those two fields are stripped before it is
passed to the application.

In the case of 802.1Q, the frame will look like this:

| Destination MAC Addr | Source MAC Addr | 802.1Q Header | EtherType | Payload |
| :---: | :---: | :---: | :---: | :---: |
| (48 bits) | (48 bits) | (32 bits) | (16 bits) | (variable) |

The most signficant (left-most) 16 bits of the 802.1Q header should have the
value 0x8100 to indicate that it is an 802.1Q frame.  The least significant
(right-most) 12 bits of the 802.1Q header should contain the value of the VLAN
ID.  The 4 bits in between can be left as zero.

Note that there are libraries, including scapy, for parsing Ethernet frames and
higher-level packets, but you may not use them for the lab.


## Working with `bytes` Instances

A `bytes` object in Python is a sequence of arbitrary byte values.  For
example:

```python
>>> bytes1 = b'\x01\x02\x03\x04\x0a\x0b\x0c\x0d'
>>> bytes2 = b'\x05\x06\x07\x08\x09'
```

The `b` prefix is always used with `bytes` objects to distinguish them from
`str` (string) objects, which have no such prefix.  In the above example,
`bytes1` and `bytes2` are assigned values from `bytes` literals.  The `\x`
notation indicates that the next two characters are hexadecimal values
containing the actual value of the byte.

A "slice" of `bytes` objects produces a new `bytes` object with only the
designated sequence.  For example, the following gets only the first two bytes
of `bytes1` (i.e., indexes 0 and 1):

```python
>>> bytes1[:2]
b'\x01\x02'
```

Likewise, the following gets only the fifth and sixth bytes of `bytes1` (i.e.,
indexes 4 and 5):

```python
>>> bytes1[4:6]
b'\n\x0b'
```

`bytes` objects can be concatenated together to yield a new `bytes` object:

```python
>>> bytes1 + bytes2
b'\x01\x02\x03\x04\n\x0b\x0c\r\x05\x06\x07\x08\t'
```

Or even:

```python
>>> bytes1[:2] + bytes1[4:6]
b'\x01\x02\n\x0b'
```

Printing out the representation of `bytes` objects can be a bit confusing.  For
example:

```python
>>> bytes1[4:6]
b'\n\x0b'
```

In this case, `\n` is the ASCII equivalent of hexadecimal 0xa (i.e., `\x0a`) or
decimal 10.  To be "helpful", Python prints out the ASCII equivalent.

To print out everything as hexademical, use the `binascii` module:

```python
>>> import binascii
>>> binascii.hexlify(bytes1[4:6])
b'0a0b'
```

Note that the result is still a `bytes` object.  To convert to `str`, use the
`decode` method:

```python
>>> binascii.hexlify(bytes1[4:6]).decode('latin1')
'0a0b'
```

Finally, to convert `bytes` objects to integers, use the `struct` module.  For
example, to put the first two bytes from a `bytes` sequence (`bytes1`) into a
short (two-byte) integer:

```python
>>> import struct
>>> short1, = struct.unpack('!H', bytes1[:2])
>>> short1 #show the value of short1 as decimal
258
>>> '%04x' % short1 #show the value of short1 as hexadecimal
'0102'
```

Or, to put the first two bytes from a `bytes` sequence (`bytes1`) into a
two one-byte integers (equivalent to `unsigned char` in C):

```python
>>> byte1, byte2 = struct.unpack('!BB', bytes1[:2])
>>> byte1 #show the value of byte1 as decimal
1
>>> byte2 #show the value of byte2 as decimal
2
>>> '%02x' % byte1 #show the value of byte1 as hexadecimal
'01'
>>> '%02x' % byte2 #show the value of byte2 as hexadecimal
'02'
```

To convert a short (two-byte) integer to a `bytes` object:

```python
>>> struct.pack('!H', 0x0102)
b'\x01\x02'
```

or:

```python
>>> struct.pack('!H', 258)
b'\x01\x02'
```

To convert two one-byte integers to a `bytes` object:

```python
>>> struct.pack('!BB', 0x1, 0x2)
b'\x01\x02'
```

or:

```python
>>> struct.pack('!BB', 1, 2)
b'\x01\x02'
```

For more info see the following:
 - [`bytes` documentation](https://docs.python.org/3/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview)
 - [`binascii` documentation](https://docs.python.org/3/library/binascii.html)
 - [`struct` documentation](https://docs.python.org/3/library/struct.html)


## Sending and Receiving Frames

The
[Cougarnet documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames)
explains how frames can be sent and received using the methods provided by the
`BaseHost` class.  In particular, you will find the `physical_interfaces()`,
`_handle_frame()`, and `send_frame()` methods very useful.  These methods are
demonstrated in a working example of a hub (`class Hub`), which forwards frames
like a switch but does not learn outgoing ports associated with MAC addresses (see the
[documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#sending-and-receiving-frames)).


## Other Helps

 - Use wireshark to capture and display frames on interfaces that you are
   interested in.  See the 
   [Cougarnet documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#working-examples)
   for examples.
 - Print to standard output or standard error.  For a script running in a
   virtual host (i.e., with the `prog` option), all output will go to the
   terminal associated with that host, assuming the terminal has not been
   disabled with `terminal=false` in the configuration file or with the
   `--terminal` command-line option.  See
   [the documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md#additional-options)
   for more.
 - You can modify `host.py` and the scenario files all you want for testing and
   for experimentation.  If this helps you, please do it!  Just note that your
   submission will be graded using only your `switch.py`; the `host.py` and
   scenario files used will be the stock files [you were provided](#resources-provided).
 - Save your work often, especially after you finish Part 1 and move on to
   Part 2.  You are encouraged to
   [commit your changes](../01b-hw-github-repo-mirror/README.md#commit-and-push-local-changes-to-private-repo).
   to the private GitHub repository that you created
   [in an earlier assignment](../01b-hw-github-repo-mirror/README.md).
   Please ensure that it remains private!


# Submission

Upload your functional `switch.py` to the assignment page on LearningSuite.
