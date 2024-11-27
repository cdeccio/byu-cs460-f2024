# Hands-On with the Application Layer

The objectives of this assignment are to gain hands-on experience with
application-layer protocols such as HTTP, DNS, and SMTP.


# Part 1 - HTTP Cookies and Conditional GET

## Maintain Your Repository

 Before beginning:
 - [Mirror the class repository](../01b-hw-private-repo-mirror), if you haven't
   already.
 - [Merge upstream changes](../01b-hw-private-repo-mirror#update-your-mirrored-repository-from-the-upstream)
   into your private repository.

 As you complete the assignment:
 - [Commit changes to your private repository](../01b-hw-private-repo-mirror#commit-and-push-local-changes-to-your-private-repo).


## Getting Started

 1. Backup and Modify `/etc/hosts`.

    First, backup your `/etc/hosts` by creating a copy of it at
    `/etc/hosts.bak`:
 
    ```bash
    $ sudo cp -pr /etc/hosts{,.bak}
    ```

    Now open `/etc/hosts` with root privileges, e.g.:

    ```bash
    $ sudo -e /etc/hosts
    ```

    Modify the first line so it looks like this:

    ```
    127.0.0.1	localhost bar.com foo.bar.com foobar.com
    ```

    Then close and save the file.  That makes it so that applications on your
    virtual machine (VM) resolve `bar.com`, `foo.bar.com`, and `foobar.com` to
    127.0.0.1, i.e., the loopback address on your system.  Thus, when your
    browser attempts to retrieve the Web page at `bar.com` (or any of the
    others), it will connect the Web server you will start on your VM
    (listening on 127.0.0.1), rather than some external host.


 2. Begin Packet Capture.  Open Wireshark:

    ```bash
    $ wireshark
    ```

    Enter "port 8000" into the capture filter field field.  Then double-click
    "Loopback: lo" to begin capturing on the loopback interface.


 3. Start Web Server.

    In another terminal window or tab, start a Python-based Web server with
    CGI-enabled from within the homework directory:

    ```bash
    $ python3 -m http.server --cgi
    ```

 4. Open Web Browser.  Open firefox, and clear all of its cache.

 5. Issue Web Requests.  From the newly-opened Web browser window, issue the
    following requests, one after the other:

    1. `http://foobar.com:8000/cgi-bin/test.cgi`
    2. `http://foo.bar.com:8000/cgi-bin/test.cgi`
    3. `http://foo.bar.com:8000/cgi-bin/test.cgi`
       (a second time - you might need to click the reload button)
    4. `http://bar.com:8000/cgi-bin/test.cgi`
    5. `http://foobar.com:8000/cgi-bin/test.cgi`
    6. `http://bar.com:8000/test123.txt`
    7. `http://bar.com:8000/byu-y-mtn2.txt`
    8. `http://bar.com:8000/test.txt`
    9. `http://bar.com:8000/test.txt`
       (a second time - you might need to click the reload button)

 6. "Update" `test.txt` by running the following command:

    ```bash
    $ touch test.txt
    ```
    (The `touch` command simply updates the timestamp of the specified file, so
    it appears newer.)

    Then re-request the following URL:

    10. `http://bar.com:8000/test.txt`
       (a third time - you might need to click the reload button)

 7. Find the frame that includes the very first HTTP request, i.e., "GET
    /cgi-bin/test.cgi", right-click on that frame, and select "Follow", then
    "TCP Stream".  You will see both the HTTP request (red) and the HTTP
    response (blue) for the selected stream in the "Follow TCP Stream" window.
    Look at the contents of the selected HTTP request to make sure that it
    matches the request you wanted to see.  (Your browser makes some extra
    requests that you should ignore).

    To switch to streams corresponding to the other HTTP requests/responses,
    modify the "Stream" field in the lower right-hand corner of the window
    (e.g., 1, 2, 3, etc.).


## Questions

Answer the following questions, using the streams corresponding to the HTTP
requests and responses issued above.  For each question that asks "why",
provide a brief but specific explanation.
 
 1. In HTTP request 1, what was the domain sent by the client in the Host
    header of the HTTP request?
 2. In HTTP request 1, was a cookie sent by the client?  Why or why not?
 3. In HTTP request 1, what was the "domain" attribute in the cookie returned
    by the server?
 4. In HTTP request 2, what was the domain sent by the client in the Host
    header of the HTTP request?
 5. In HTTP request 2, was the cookie sent by the client?  What does the answer
    (yes/no) tell you about the ability or inability of the server to set a
    cookie with a "domain" attribute other than its own domain name (i.e., the
    domain name in the URL)?
 6. In HTTP request 2, what was the "domain" attribute in the cookie returned
    by the server?
 7. In HTTP request 3, what was the domain sent by the client in the Host
    header of the HTTP request?
 8. In HTTP request 3, was the cookie sent by the client?  What does the answer
    (yes/no) tell you about the ability or inability of the server to set a
    cookie with a "domain" attribute other than its own domain name (i.e., the
    domain name in the URL)?
 9. In HTTP request 3, was a cookie sent by the client?  Why or why not?
 10. In HTTP request 4, was a cookie sent by the client?  Why or why not?
 11. In HTTP request 5, was a cookie sent by the client?  Why or why not?
 12. In HTTP request 6, was a cookie sent by the client?  Why or why not?
 13. What was the response code associated with request 6?  Why?
 14. What was the response code associated with request 7?  Why?
 15. What is the content type communicated by the server to the client with the
     "Content-Type" header in request 7?
 16. What type of characters were used for the request headers in request 7?
 17. What type of characters were used for the response headers in request 7?
 18. What type of characters were used for the response body in request 7?
     (Hint: look all the way through the response body.)
 19. What must a client do to display the image properly?
 20. What was the response code associated with request 8?  Why?
 21. What was the content type communicated by the server to the client with the
     "Content-Type" header in request 8?
 22. What was the response code associated with request 9?  Why was it
     different than that of request 8?
 23. What was the response code associated with request 10?  Why was it
     different than that of request 9?


## Cleanup

 1. Revert to your backup of `/etc/hosts`:

    ```
    sudo mv /etc/hosts{.bak,}
    ```

 2. Close Wireshark.

 3. Close Firefox.


# Part 2 - TCP Fast Open

This part is an exercise to help you understand TCP Fast Open (TFO).  The
script `tfo_echo.py` can be run both as an echo client and an echo server,
depending on the presence of the `-l` option.  When the script is run with the
`-f` option (whther client or server), TFO is used.


## Getting Started

 1. Start cougarnet.  File `h2-s1.cfg` contains a configuration file that
    describes a network with two hosts, `a` and `b`, directly connected.

    Run the following command to create and start the network:

    ```bash
    $ cougarnet --display --wireshark=a-b h2-s1.cfg
    ```

 2. Start and interact with an echo server. Run the following on host `b` to
    start the echo server:

    ```bash
    b$ python3 tfo_echo.py -l 5599
    ```

    On host `a`, running the following to run the client:

    ```bash
    a$ python3 tfo_echo.py 10.0.0.2 5599 foobar
    ```


## Questions (1)

Answer the following questions about the packet capture:

 24. What was the segment length (i.e., the TCP payload) associated with the
     SYN packet?

 25. Was there a TFO option in the TCP header of the SYN packet?  If so, was
     there a cookie?

 26. What was the relative acknowledgement number associated with the SYNACK
     packet?

 27. Was there a TFO option in the TCP header of the SYNACK packet?  If so, was
     there a cookie?

 28. How many RTTs did it take for the string "echoed" by the server to be
     received by the client, including connection establishment?  (Note: don't
     actually add up the time; just think about and perhaps draw out the back
     and forth interactions between client and server.)



## Enabling and Priming TFO

Use `Ctrl`-`c` on host `b` to interrupt the running echo server.  Then run
the following on both host `a` and host `b`:

```bash
$ sudo sysctl net.ipv4.tcp_fastopen=3
```

Depending on the value passed to the `net.ipv4.tcp_fastopen` value, TFO might
be enabled for only when the host is acting as a TCP client, only when the host
is acting as a TCP server, or both.  The value 3 enables TFO from both a client
perspective _and_ a server perspective.

Restart the server on host `b` with the following command (note the presence of
the `-f` option):

```bash
b$ python3 tfo_echo.py -f -l 5599
```

Now run the client again on host `a` with the following command (note the
presence of the `-f` option):

```bash
a$ python3 tfo_echo.py -f 10.0.0.2 5599 foobar
```


## Questions (2)

For questions 29 - 33, answer the same questions as 24 - 28, but for the most
recent test.


## Using TFO

Finally, restart the server on host `b` with the following command:

```bash
b$ python3 tfo_echo.py -f -l 5599
```

Then run the following again:

```bash
a$ python3 tfo_echo.py -f 10.0.0.2 5599 foobar
```


## Questions (3)

For questions 34 - 38, answer the same questions as 24 - 28, but for the most
recent test.


 39. Looking `tfo_echo.py`, what key differences are involved in programming a
     TFO connection (vs. a non-TFO TCP connection) from the perspective of the
     _client_.


# Part 3 - SMTP

This part is an exercise to help you understand SMTP.

## Getting Started

 1. Install swaks (Swiss Army Knife SMTP). Run the following to install swaks:

    ```
    sudo apt install swaks
    ```

 2. Start cougarnet.  File `h2-s1.cfg` contains a configuration file that
    describes a network with two hosts, `a` and `b`, directly connected.

    Run the following command to create and start the network:

    ```bash
    cougarnet --display --wireshark=a-b h2-s1.cfg
    ```

 3. Start a "debugging" SMTP server on host `b`:

    ```bash
    b$ sudo python3 -m smtpd -n --class DebuggingServer 0.0.0.0:25
    ```

    This Python SMTP server simply interacts with clients over SMTP and prints
    the messages it receives to standard output.

 4. Send a message.  On host `a`, execute the following to send an email
    message from host `a` to host `b`:

    ```bash
    a$ swaks --server 10.0.0.2 --to joe@example.com
    ```

 5. Send a message with attachment.  On host `a`, execute the following to send
    an email message with an attachment from host `a` to host `b`:

    ```bash
    a$ swaks --server 10.0.0.2 --attach byu-y-mtn2.jpg --to joe@example.com
    ```

 6. Follow TCP Streams.  For the emails sent in #5 and #6, open the
    corresponding TCP stream by following the instructions below:

 7. Find a frame that is part of the first SMTP interaction.  Right-click on
    that frame, and select "Follow", then "TCP Stream".  You will see the
    entire SMTP conversation, including both server (blue) and client (red).
    Look at the contents of the SMTP session to make sure that it matches the
    one that you wanted to see.

    To switch to streams corresponding to the other SMTP conversation, modify
    the "Stream" field in the lower right-hand corner of the window (e.g., 1,
    2, 3, etc.).


## Questions

Answer the following questions, using the streams corresponding to the SMTP
communications and responses issued above.  For each question that asks "why",
provide a brief but specific explanation.


 40. With SMTP, who initiates the SMTP conversation - client or server?
 41. What command does the client use to introduce itself?
 42. What command does the client use to send the actual email headers and
     message body?
 43. How does the client indicate to the server that it is done sending the
     email message?
 44. What numerical response code did the server return for the `MAIL FROM`,
     and `RCPT TO` commands?
 45. What numerical response code did the server return for the `QUIT` command?
 46. What is the makeup of the image attachment in the second email, as seen
     "on the wire".
 47. What must a client do to display the image properly?
