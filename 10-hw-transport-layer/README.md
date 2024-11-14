# Hands-On with the Transport Layer

The objectives of this assignment are to gain hands-on experience with TCP and
TCP Fast Open (TFO).


# Getting Started

## Maintain Your Repository

 Before beginning:
 - [Mirror the class repository](../01b-hw-private-repo-mirror), if you haven't
   already.
 - [Merge upstream changes](../01b-hw-private-repo-mirror#update-your-mirrored-repository-from-the-upstream)
   into your private repository.

 As you complete the assignment:
 - [Commit changes to your private repository](../01b-hw-private-repo-mirror#commit-and-push-local-changes-to-your-private-repo).


## Install Dependencies

Make sure that `curl` is installed.

```
$ sudo apt install curl
```

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


## Start the Network

File `h2-s1.cfg` contains a configuration file that describes a network with
two hosts, `a` and `b`, connected to switch `s1`.

Run the following command to create and start the network:

```bash
cougarnet --display --wireshark=a-s1 h2-s1.cfg
```

Wireshark will automatically open, capturing packets on the device associated
with the link between `a` and `s1`.


# Part 1 - Analysis of TCP Three-Way Handshake and MSS

Make sure you are in the directory that contains `byu-y-mtn.jpg`.  Then run the
following command on host `b` to start an HTTP server listening for incoming
HTTP requests on port 8000:

```bash
b$ python3 -m http.server
```

On host `a` run the following:

```bash
a$ curl -o /dev/null http://10.0.0.2:8000/byu-y-mtn.jpg
```

This will request the file `byu-y-mtn.jpg` from 10.0.0.2 (host `b`) port 8000
and store it to `/dev/null` (nowhere).

Now go to the Wireshark output, and use the packets associated with
the TCP three-way handshake to answer the following questions:

 1. What is the raw sequence number in the SYN packet?

 2. What is the relative sequence number in the SYN packet (i.e., relative to
    the raw sequence number)?

 3. What is the raw sequence number in the SYNACK packet?

 4. What is the relative sequence number in the SYNACK packet (i.e., relative
    to the raw sequence number)?

 5. What is the raw acknowledgment number in the SYNACK packet?

 6. What is the relative acknowledgment number in the SYNACK packet (i.e.,
    relative to the raw acknowledgment number)?

 7. What is the raw sequence number in the ACK packet?

 8. What is the relative sequence number in the ACK packet (i.e., relative
    to the raw sequence number)?

 9. What is the raw acknowledgment number in the ACK packet?

 10. What is the relative acknowledgment number in the ACK packet (i.e.,
     relative to the raw acknowledgment number)?

 11. What MSS value does the client advertise to the server in the TCP option
     of the SYN packet?

 12. What MSS value does the server advertise to the client in the TCP option
     of the SYNACK packet?


# Part 2 - Analysis of Large HTTP Response

Continue using the running cougarnet scenario and Wireshark instance from the
previous part.

In the Wireshark window, following the packets corresponding to the TCP
three-way handshake, you will see a TCP segment from 10.0.0.1 containing an
HTTP GET request and a lot of TCP segments from 10.0.0.2 containing the HTTP
response.

Right-click on one of the packets, then hover over "Protocol Preferences" in
the menu that appears, then "Transmission Control Protocol".  Now _uncheck_ the
box that says "Allow subdissector to reassemble TCP streams.  When
"reassembling" is enabled, Wireshark combines all TCP segments associated with
a single HTTP response, which behavior is confusing when analyzing TCP.  Once
unchecked, you should see the individual segments associated with separate
packets.

Now select "Statistics" from the Wireshark menu.  Then hover over "TCP Stream
Graphs" in the menu that appears.  Finally, click on "Time Sequence (Stevens").

In the graph, the each dot represents a TCP segment being sent by `b` (the HTTP
server responding to the HTTP request), the sequence number of which is the
y-value of the dot.  The almost-vertical stacks of dots represent TCP segments
that are sent back-to-back.  The "width" of a stack represents the time
required to transmit those segments--that is, the x-value of the last segment
in the stack minus the x-value of the first segment in the stack.  The
horizontal lines in between stacks represent the time in which the host is
waiting, idle, for in-flight bytes to be acknowledged before sending more.
Thus, initially, the length of these lines is very close to the round-trip time
(RTT), i.e., the time it takes for the segments to propagate to their
destination and the acknowledgments to propagate back to the sender.  

Answer the questions below:

 13. Beginning at time 0, when the first stack of segments (i.e., round 1) is
    issued, through the time the eighth stack of segments (i.e., round 8) is
    issued, how does the send window grow?  That is, how does the number of
    bytes (and segments) sent in round `i` compare to the number sent in round
    `i - 1`?

 14. Based on your response to the previous problem, what congestion control
    state would you say that the sender is in during the sending of these first
    8 rounds?

 15. How does the idle time change as the rounds increase?  Briefly explain why.

 16. Explain what the graph will look like if the current pattern holds.


# Part 2 - TCP Flow Control

Continue using the running cougarnet scenario and Wireshark instance for this
exercise.  Close the "Time Sequence" window in Wireshark.  Then click the
"Restart current capture" button from the Wireshark instance to clear all the
packets captured in Part 2.

On host `b` enter `Ctrl`+`c` to stop the HTTP server.  Then start an
interactive Python shell on host `b` by entering the following:

```bash
b$ python3
```

Enter the following into the interactive Python shell opened on host `b`:

```
>>> import socket
>>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> s.bind(('0.0.0.0', 5599))
>>> s.listen()
>>> s1, addr = s.accept()
```

This starts a TCP server socket, listening for incoming connections on
port 5599.  Note that the prompt will not return after the call to `accept()`;
`accept()` only returns when a client has initiated a connection to the server.
We will do that next, from host `a`.

On host `a` run the following to start an interactive Python shell:

```bash
a$ python3
```

Enter the following into the interactive Python shell opened on host `a`:

```
>>> import socket
>>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> s.connect(('10.0.0.2', 5599))
>>> s.send(b'\x00' * 5000000)
```

This creates a TCP client socket and connects it to the server running on host
`b`.  It then calls `send()` with 5 million bytes of data (all value 0) to be
sent.

Note two things.  First, `recv()` was never called on the socket `s1` on host
`b`.  Thus, any data sent to that socket from the client is never retrieved
from the socket's "ready" buffer and passed to the application.  Second, the
`send()` call on the socket `s` on host `a` has not returned.  To further
examine this, answer the following questions.

 17. Look at the last TCP packet from host 10.0.0.1.  What is the value of the
     window field in the packet?

 18. What is the cause of the value observed in the window field?

Now add the following line on host `b`'s Python shell:

```python
>>> buf = s1.recv(1000000)
```

 19. What do you observe in the Wireshark window after entering that code?

 20. What is the cause of the changes observed in the Wireshark window?
