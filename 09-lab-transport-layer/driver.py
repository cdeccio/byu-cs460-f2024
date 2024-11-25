#!/usr/bin/env python3

import re
import signal
import subprocess
import sys

LOG_PREFIX = r'^(?P<time>\d+\.\d+)\s+(?P<hostname>\S+)\s+'
LOG_START_RE = re.compile(LOG_PREFIX + r'START$')
LOG_STOP_RE = re.compile(LOG_PREFIX + r'STOP$')
LOG_ARP_RECV_RE = re.compile(LOG_PREFIX + \
        r'Received ARP (?P<type>REQUEST|REPLY) ' + \
        r'from (?P<src_ip>\d+\.\d+\.\d+\.\d+)/' + \
        r'(?P<src_mac>[0-9a-f]{2}(:[0-9a-f]{2}){5}) for (\d+\.\d+\.\d+\.\d+)')
LOG_ICMP_RECV_RE = re.compile(LOG_PREFIX + \
        r'Received ICMP packet from (?P<src_ip>\d+\.\d+\.\d+\.\d+)')
LOG_OTHER_RE = re.compile(LOG_PREFIX + r'(?P<rest>.*)$')

NEXT_ITERATION_SLACK = 0.15 # 150 ms
MAX_INTERVAL = 0.5 # 500 ms
INTERVAL = 1.0

class Lab4Tester:
    cmd = []
    expected_observations = []

    def evaluate(self, iteration, time_seen, observations):
        raise NotImplemented

    def evaluate_lines(self, lines):
        # initialize
        start_time = None
        max_time = None
        next_time = None
        iteration = None
        observations = None

        evaluated = 0
        success = 0

        for line in lines:
            m = LOG_START_RE.search(line)
            if m is not None:
                start_time = float(m.group('time')) + INTERVAL
                max_time = start_time + MAX_INTERVAL
                next_time = start_time + (INTERVAL - NEXT_ITERATION_SLACK)
                iteration = 0
                observations = []
                continue

            cat = ''
            rest = ''
            m = LOG_ARP_RECV_RE.search(line)
            if m is not None:
                hostname = m.group('hostname')
                if m.group('type') == 'REQUEST':
                    cat = 'ARP_REQUEST'
                else:
                    cat = 'ARP_REPLY'
            else:
                m = LOG_ICMP_RECV_RE.search(line)
                if m is not None:
                    hostname = m.group('hostname')
                    cat = 'ICMP'

                else:
                    m = LOG_STOP_RE.search(line)
                    if m is not None:
                        hostname = ''
                        cat = ''
                    else:
                        m = LOG_OTHER_RE.search(line)
                        if m is not None:
                            hostname = m.group('hostname')
                            cat = 'OTHER'
                            rest = m.group('rest')

            if m is None:
                continue

            mytime = float(m.group('time'))

            while mytime > max_time:
                if not observations:
                    # if we have gone through the loop more than once, then
                    # don't reduce by NEXT_ITERATION_SLACK
                    start_time = start_time + NEXT_ITERATION_SLACK
                    next_time = next_time + NEXT_ITERATION_SLACK

                # evaluate
                result = self.evaluate(iteration, start_time, observations)
                if result is not None:
                    evaluated += 1
                    if result:
                        success += 1

                # reset
                iteration += 1
                start_time = next_time

                max_time = start_time + MAX_INTERVAL
                next_time = start_time + (INTERVAL - NEXT_ITERATION_SLACK)
                observations = []

            if not observations:
                # if this is the first host seen, then save the time
                start_time = mytime
                max_time = start_time + MAX_INTERVAL
                next_time = start_time + (INTERVAL - NEXT_ITERATION_SLACK)

            observations.append((cat, hostname, rest))

        # evaluate
        result = self.evaluate(iteration, start_time, observations)
        if result is not None:
            evaluated += 1
            if result:
                success += 1

        return success, evaluated

    def run(self):
        p = None
        try:
            p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE)
            p.wait()
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
            p.wait()
            raise

        output = p.stdout.read().decode('utf-8')
        output_lines = output.splitlines()
        return self.evaluate_lines(output_lines)

class Scenario1(Lab4Tester):
    cmd = ['cougarnet', '--stop=14', '--disable-ipv6',
            '--terminal=none', 'scenario1.cfg']

    UDP_MSG_STR = r'UDP msg \((?P<srcaddr>\d+\.\d+\.\d+\.\d+):(?P<srcport>\d+) -> (?P<dstaddr>\d+\.\d+\.\d+\.\d+):(?P<dstport>\d+)\): (?P<msg>.+)'

    NETCAT_MSG_RE = re.compile(r'^Netcat (sending|received) UDP msg (to|from) (?P<addr>\d+\.\d+\.\d+\.\d+):(?P<port>\d+): (?P<msg>.+)$')
    ECHO_MSG_RE = re.compile(r'^Echo server received UDP msg from (?P<srcaddr>\d+\.\d+\.\d+\.\d+):(?P<srcport>\d+): (?P<msg>.+)$')
    HOST_UDP_MSG_RE = re.compile(r'^Host received ' + UDP_MSG_STR + '$')
    HOST_ICMP_MSG_RE = re.compile(r'^Host received ICMP \(type=(?P<type>\d+), code=(?P<code>\d+)\), ' + UDP_MSG_STR + '$')

    def __init__(self):
        super()
        self.eval_count = 0
        self.eval_mapping = [
                self.evaluate0,
                self.evaluate1,
                self.evaluate2,
                self.evaluate2,
                ]

    def evaluate0(self, iteration, time_seen, observations):
        #[('OTHER', 'a', 'Netcat sending UDP msg to 10.0.0.2:1234: abcdefghijklmnop'),
        #('OTHER', 'b', 'Host received UDP msg (10.0.0.1:23746 -> 10.0.0.2:1234): abcdefghijklmnop'),
        #('OTHER', 'a', 'Host received ICMP (type=3, code=3), UDP msg (10.0.0.1:23746 -> 10.0.0.2:1234): abcdefghijklmnop')]

        if not observations:
            sys.stderr.write('Expected netcat UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat_match = self.NETCAT_MSG_RE.search(msg)
        if netcat_match is None:
            sys.stderr.write('Expected netcat UDP message\n')
            return False

        if not observations:
            sys.stderr.write('Expected UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_UDP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected UDP message\n')
            return False

        if not observations:
            return True
        cat, hostname, msg = observations.pop(0)
        icmp_match = self.HOST_ICMP_MSG_RE.search(msg)
        if hostname == 'a' and icmp_match is not None and \
                icmp_match.group('type') == '3' and \
                icmp_match.group('code') == '3' and \
                icmp_match.group('srcaddr') == host_match.group('srcaddr') and \
                icmp_match.group('dstaddr') == host_match.group('dstaddr') and \
                icmp_match.group('srcport') == host_match.group('srcport') and \
                icmp_match.group('dstport') == host_match.group('dstport') and \
                icmp_match.group('msg') == host_match.group('msg'):
            sys.stderr.write('Extra credit for ICMP message\n')
        else:
            sys.stderr.write('Malformed ICMP message\n')

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def evaluate1(self, iteration, time_seen, observations):
        return None

    def evaluate2(self, iteration, time_seen, observations):
        #[('OTHER', 'a', 'Netcat sending UDP msg to 10.0.0.2:1234: abcdefghijklmnop'),
        #('OTHER', 'b', 'Host received UDP msg (10.0.0.1:23746 -> 10.0.0.2:1234): abcdefghijklmnop'),
        #('OTHER', 'b', 'Echo server received UDP msg from 10.0.0.1:23746: abcdefghijklmnop'),
        #('OTHER', 'a', 'Host received UDP msg (10.0.0.2:1234 -> 10.0.0.1:23746): abcdefghijklmnop'),
        #('OTHER', 'a', 'Netcat received UDP msg from 10.0.0.2:1234: abcdefghijklmnop')]
        if not observations:
            sys.stderr.write('Expected netcat UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat_match = self.NETCAT_MSG_RE.search(msg)
        if netcat_match is None:
            sys.stderr.write('Expected netcat UDP message\n')
            return False

        if not observations:
            sys.stderr.write('Expected UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_UDP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected UDP message\n')
            return False

        if not observations:
            sys.stderr.write('Expected echo UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        echo_match = self.ECHO_MSG_RE.search(msg)
        if hostname == 'b' and echo_match is not None and \
                echo_match.group('srcaddr') == host_match.group('srcaddr') and \
                echo_match.group('srcport') == host_match.group('srcport') and \
                echo_match.group('msg') == host_match.group('msg'):
            pass
        else:
            sys.stderr.write('Malformed echo UDP message\n')
            return False

        if not observations:
            sys.stderr.write('Expected UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_UDP_MSG_RE.search(msg)
        if hostname in ('a', 'c') and host2_match is not None and \
                host2_match.group('srcaddr') == host_match.group('dstaddr') and \
                host2_match.group('dstaddr') == host_match.group('srcaddr') and \
                host2_match.group('srcport') == host_match.group('dstport') and \
                host2_match.group('dstport') == host_match.group('srcport') and \
                host2_match.group('msg') == host_match.group('msg'):
            pass
        else:
            sys.stderr.write('Malformed UDP message\n')
            return False

        if not observations:
            sys.stderr.write('Expected netcat UDP message\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat2_match = self.NETCAT_MSG_RE.search(msg)
        if hostname in ('a', 'c') and netcat2_match is not None and \
                netcat2_match.group('addr') == host2_match.group('srcaddr') and \
                netcat2_match.group('port') == host2_match.group('srcport') and \
                netcat2_match.group('msg') == host2_match.group('msg'):
            pass
        else:
            sys.stderr.write('Expected netcat UDP message\n')
            return False

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def evaluate(self, iteration, time_seen, observations):
        curr = self.eval_count
        self.eval_count += 1
        if curr >= len(self.eval_mapping):
            return None
        return self.eval_mapping[curr](iteration, time_seen, observations)
                            
class Scenario2(Lab4Tester):
    cmd = ['cougarnet', '--stop=25', '--disable-ipv6',
            '--terminal=none', 'scenario2.cfg']

#('OTHER', 'b', 'Host received TCP packet (10.0.0.1:65013 -> 10.0.0.2:1234)    Flags: S, Seq=37349, Ack=0'), ('OTHER', 'a', 'Host received TCP packet (10.0.0.2:1234 -> 10.0.0.1:65013)    Flags: R, Seq=0, Ack=0')]
#[]
#[('OTHER', 'b', 'Host received TCP packet (10.0.0.1:62963 -> 10.0.0.2:1234)    Flags: S, Seq=5945, Ack=0'), ('OTHER', 'a', 'Host received TCP packet (10.0.0.2:1234 -> 10.0.0.1:62963)    Flags: SA, Seq=53337, Ack=5946'), ('OTHER', 'b', 'Host received TCP packet (10.0.0.1:62963 -> 10.0.0.2:1234)    Flags: A, Seq=5946, Ack=53338')]
#[('OTHER', 'b', 'Host received TCP packet (10.0.0.1:11503 -> 10.0.0.2:1234)    Flags: A, Seq=2747044733, Ack=985193125'), ('OTHER', 'a', 'Host received TCP packet (10.0.0.2:1234 -> 10.0.0.1:11503)    Flags: R, Seq=0, Ack=0')]
#[('OTHER', 'b', 'Host received TCP packet (10.0.0.3:7814 -> 10.0.0.2:1234)    Flags: S, Seq=43350, Ack=0'), ('OTHER', 'c', 'Host received TCP packet (10.0.0.2:1234 -> 10.0.0.3:7814)    Flags: SA, Seq=58981, Ack=43351'), ('OTHER', 'b', 'Host received TCP packet (10.0.0.3:7814 -> 10.0.0.2:1234)    Flags: A, Seq=43351, Ack=58982')]
#[('', '', '')]

    TCP_MSG_STR = r'TCP packet \((?P<srcaddr>\d+\.\d+\.\d+\.\d+):(?P<srcport>\d+) -> (?P<dstaddr>\d+\.\d+\.\d+\.\d+):(?P<dstport>\d+)\)\s+Flags: (?P<flags>[A-Z]+), Seq=(?P<seq>\d+), Ack=(?P<ack>\d+)'

    HOST_TCP_MSG_RE = re.compile(r'^Host received ' + TCP_MSG_STR + '$')

    def __init__(self):
        super()
        self.eval_count = 0
        self.eval_mapping = [
                self.not_listening,
                self.blank,
                self.new_connection,
                self.not_listening,
                self.new_connection,
                ]

    def not_listening(self, iteration, time_seen, observations):
        if not observations:
            sys.stderr.write('Expected SYN packet\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if hostname == 'b' and host_match is not None and \
                host_match.group('flags') in ('S', 'A'):
            pass
        else:
            sys.stderr.write('Malformed SYN packet\n')
            return False

        if not observations:
            return True
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if hostname in ('a', 'c') and host2_match is not None and \
                host2_match.group('srcport') == host_match.group('dstport') and \
                host2_match.group('dstport') == host_match.group('srcport') and \
                host2_match.group('srcaddr') == host_match.group('dstaddr') and \
                host2_match.group('dstaddr') == host_match.group('srcaddr') and \
                host2_match.group('flags') == 'R':
            sys.stderr.write('Extra credit for TCP RST\n')
        else:
            sys.stderr.write('Malformed RST packet\n')

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def blank(self, iteration, time_seen, observations):
        return None

    def new_connection(self, iteration, time_seen, observations):
        if not observations:
            sys.stderr.write('Expected SYN packet"\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if hostname == 'b' and host_match is not None and \
                host_match.group('flags') == 'S':
            pass
        else:
            sys.stderr.write('Malformed SYN packet\n')
            return False

        if not observations:
            sys.stderr.write('Expected SYNACK packet\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if hostname in ('a', 'c') and \
                host2_match.group('srcport') == host_match.group('dstport') and \
                host2_match.group('dstport') == host_match.group('srcport') and \
                host2_match.group('srcaddr') == host_match.group('dstaddr') and \
                host2_match.group('dstaddr') == host_match.group('srcaddr') and \
                int(host2_match.group('ack')) == int(host_match.group('seq')) + 1 and \
                host2_match.group('flags') == 'SA':
            pass
        else:
            sys.stderr.write('Malformed SYNACK packet\n')
            return False

        if not observations:
            sys.stderr.write('Expected ACK packet\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host3_match = self.HOST_TCP_MSG_RE.search(msg)
        if hostname == 'b' and \
                host3_match.group('srcport') == host_match.group('srcport') and \
                host3_match.group('dstport') == host_match.group('dstport') and \
                host3_match.group('srcaddr') == host_match.group('srcaddr') and \
                host3_match.group('dstaddr') == host_match.group('dstaddr') and \
                int(host3_match.group('ack')) == int(host2_match.group('seq')) + 1 and \
                int(host3_match.group('seq')) == int(host_match.group('seq')) + 1 and \
                host3_match.group('flags') == 'A':
            pass
        else:
            sys.stderr.write('Malformed ACK packet\n')
            return False

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def evaluate(self, iteration, time_seen, observations):
        curr = self.eval_count
        self.eval_count += 1
        if curr >= len(self.eval_mapping):
            return None
        return self.eval_mapping[curr](iteration, time_seen, observations)
                            
def main():
    try:
        for scenario in Scenario1, Scenario2:
            print(f'Running {scenario.__name__}...')
            tester = scenario()
            success, total = tester.run()
            sys.stderr.write(f'  Result: {success}/{total}\n')
    except KeyboardInterrupt:
        sys.stderr.write('Interrupted\n')
    sys.stderr.write('''PLEASE NOTE: this driver shows the result of the
various tests but does not currently show the weighted value of each
test.\n''')

if __name__ == '__main__':
    main()
