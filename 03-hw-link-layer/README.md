# Hands-On with the Link Layer

The objective of this assignment is gain hands-on experience with switches and
VLANS.


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


## Start the Network

File `h6-s2-vlan.cfg` contains a configuration file that describes a network
with six hosts: `a` through `c` connected to switch `s1`, `d` through `f`
connected to switch `s2`, and `s1` and `s2` connected to each other.  Also,
hosts `a`, `b`, `d`, and `e` are on VLAN 25, while hosts `c` and `f` are on
VLAN 30.
   
Run the following command to create and start the network:

```bash
$ cougarnet --wireshark a-s1,b-s1,c-s1,d-s2,e-s2,f-s2,s1-s2 --display --disable-ipv6 h6-s2-vlan.cfg
```

The `--display` option tells Cougarnet to print out the network layout before
starting all the hosts.  The `--disable-ipv6` option disables IPv6 because an
IPv6-enabled host introduces packets into the network that will cause our
switch to learn things from packets other than those we explicitly place on the
network.  The `--wireshark` option tells Cougarnet to open Wireshark and begin
capturing on the following interfaces:

 * `a-s1` (host `a`'s interface that connects it to `s1`)
 * `b-s1` (host `b`'s interface that connects it to `s1`)
 * `c-s1` (host `c`'s interface that connects it to `s1`)
 * `d-s2` (host `d`'s interface that connects it to `s2`)
 * `e-s2` (host `e`'s interface that connects it to `s2`)
 * `f-s2` (host `f`'s interface that connects it to `s2`)
 * `s1-s2` (host `s1`'s interface that connects it to `s2`)

Because of the current configuration, you will only see three terminals show
up, one associated with host `b`, one associated with host `e`, and one
associated with switch `s1`.


## Prepare the Host for Link-Layer Analysis

The following instructions prepare the network for our experiments, allowing us
to focus on the link layer.

Run the following in host `b`:

```bash
b$ sudo ip neigh add 10.0.0.5 lladdr 00:00:00:ee:ee:ee dev b-s1
b$ sudo iptables -I INPUT -j DROP
```

(Where `b$` is simply the prompt associated with host `b`.)

and run the following in host `e`:

```bash
e$ sudo ip neigh add 10.0.0.2 lladdr 00:00:00:bb:bb:bb dev e-s2
e$ sudo iptables -I INPUT -j DROP
```

The first line in each snippet (i.e., the `ip neigh` command) simply hard-codes
the MAC address for the given destination device (we know the MAC address
because set it explicitly in the config file), so it doesn't need to be found
through ARP--another protocol, which we haven't studied yet.  The second line
in each snippet (i.e., `iptables`) blocks any packets from getting through,
with a firewall rule.  This allows us to do a `ping` and only focus on the
request (i.e., because a response will never be seen).

Finally, reset the MAC address tables in each of the switches by running the
following from the `s1` terminal:

```bash
s1$ sudo ovs-appctl fdb/flush s1
s1$ sudo ovs-appctl fdb/flush s2
```


# Exercise

 1. Run the following command on `s1` to show the state of the MAC address
    tables:

    ```bash
    s1$ sudo ovs-appctl fdb/show s1
    s1$ sudo ovs-appctl fdb/show s2
    ```

    For which hosts are there entries in `s1`'s switch table?

 2. For which hosts are there entries in `s2`'s switch table?

 3. Run the following command on `b` to send a single frame from `b` to `e`:
   
    ```bash
    b$ ping -c 1 -W 1 10.0.0.5
    ```

    (The `-c` option tells `ping` to send just one packet, and the `-W` option
    tells `ping` to only wait for one second for a response--remember, we have
    enabled a firewall on `e`, so a response won't be sent.)

    In the Wireshark window, sort the running packet capture by the "Time"
    column.  The rows in the captures all represent the same frame as seen by
    different interfaces.

    Which hosts observed the frame from `b` to `e`?  Hint: the name of the
    interface on which a frame was seen can be found in the "Frame" layer in
    Wireshark.  Each interface name corresponds to the names of the two devices
    to which it is connected, e.g., interface `a-s1` represents the interface
    on host `a` that connects it to switch `s1`.  Also, do not include the
    original frame from `b` to `s1`; only indicate `b` if you see a second
    frame that was forwarded from `s1` to `b`.

 4. On which link(s) (i.e., between which two network components) do/does the
    frame(s) include an 802.1Q frame header?

 5. What is the value of the ID field in the 802.1Q header of that frame?
    
 6. Run the following command on `s1` to show the state of the MAC address
    tables:

    ```bash
    s1$ sudo ovs-appctl fdb/show s1
    s1$ sudo ovs-appctl fdb/show s2
    ```

    (Note: entries expire after five minutes, so if no entries show up, then
    re-run the `ping` command from question 3 to re-create any entries.)

    For which hosts are there entries in `s1`'s switch table?

 7.  For which hosts are there entries in `s2`'s switch table?


 8. Run the following command on `e` to send a single frame from `e` to `b`:
   
    ```bash
    e$ ping -c 1 -W 1 10.0.0.2
    ```

    Look again at the running packet capture, sorted by the "Time" column.

    Which hosts observed the frame from `e` to `b`?

 9. Run the following command on `s1` to show the state of the MAC address
    tables:

    ```bash
    s1$ sudo ovs-appctl fdb/show s1
    s1$ sudo ovs-appctl fdb/show s2
    ```

    For which hosts are there entries in `s1`'s switch table?

 10. For which hosts are there entries in `s2`'s switch table?

 11. Go back to the terminal from which you started the network.  It should say:
     `Ctrl-c to quit`.  Now enter `Ctrl`-`c`.  Then re-start the network with
     the following:
   
     ```bash
     $ cougarnet --display --disable-ipv6 h6-s2-vlan.cfg
     ```

     Note that you haven't enabled firewalls as you did
     [previously](#prepare-the-host-for-link-layer-analysis).
     Now run the following from host `b`:

     ```bash
     b$ ping -c 5 -W 1 10.0.0.5
     ```

     Then:

     ```bash
     b$ ping -c 5 -W 1 10.0.0.3
     ```

     What is the difference between pinging `e` and pinging `c`?  Why is there a
     difference?


 12. Now stop (`Ctrl`-`c`) the network and re-start a variant of the previous
     configuration with:
    
     ```bash
     $ cougarnet --display --disable-ipv6 h6-s2.cfg
     ```

     Now run the following from host `b`:

     ```bash
     b$ ping -c 5 -W 1 10.0.0.5
     ```

     Then:

     ```bash
     b$ ping -c 5 -W 1 10.0.0.3
     ```

     Is the outcome different than it was in the previous problem?  Why or why
     not?  Use the difference in configuration files to determine the answer.
