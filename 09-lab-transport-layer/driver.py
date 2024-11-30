#!/usr/bin/env python3

import json
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
        if not observations:
            sys.stderr.write('Expected netcat UDP message leaving a\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat_match = self.NETCAT_MSG_RE.search(msg)
        if netcat_match is None:
            sys.stderr.write('Expected netcat UDP message leaving a\n')
            return False

        if not observations:
            sys.stderr.write('Expected UDP message arriving at b\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_UDP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected UDP message arriving at b\n')
            return False

        # The next packet is optional
        if not observations:
            return True

        cat, hostname, msg = observations.pop(0)
        icmp_match = self.HOST_ICMP_MSG_RE.search(msg)
        if icmp_match is None:
            sys.stderr.write('Expected an ICMP error message at a, if anything.\n')
            return False
        icmp_correct = { 'type': '3',
                        'code': '3',
                        'srcaddr': host_match.group('srcaddr'),
                        'dstaddr': host_match.group('dstaddr'),
                        'srcport': host_match.group('srcport'),
                        'dstport': host_match.group('dstport'),
                        'msg': host_match.group('msg') }
        icmp_observed = {
                'type': icmp_match.group('type'),
                'code': icmp_match.group('code'),
                'srcaddr': icmp_match.group('srcaddr'),
                'dstaddr': icmp_match.group('dstaddr'),
                'srcport': icmp_match.group('srcport'),
                'dstport': icmp_match.group('dstport'),
                }
        if hostname != 'a':
            sys.stderr.write('ICMP error message was expected at a, not %s\n' % \
                    hostname)
        elif icmp_observed != icmp_correct:
            sys.stderr.write('ICMP message malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(icmp_correct), json.dumps(icmp_observed)))
        else:
            sys.stderr.write('Extra credit for ICMP message\n')

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def evaluate1(self, iteration, time_seen, observations):
        return None

    def evaluate2(self, iteration, time_seen, observations):
        if not observations:
            sys.stderr.write('Expected netcat UDP message leaving a\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat_match = self.NETCAT_MSG_RE.search(msg)
        if netcat_match is None:
            sys.stderr.write('Expected netcat UDP message leaving a\n')
            return False

        if not observations:
            sys.stderr.write('Expected UDP message arriving at b\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_UDP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected UDP message arriving at b\n')
            return False

        if not observations:
            sys.stderr.write('Expected echo UDP message arriving at b\n')
            return False
        cat, hostname, msg = observations.pop(0)
        echo_match = self.ECHO_MSG_RE.search(msg)
        if echo_match is None:
            sys.stderr.write('Expected echo UDP message arriving at b\n')
            return False
        echo_correct = { 'srcaddr': host_match.group('srcaddr'),
                        'srcport': host_match.group('srcport'),
                        'msg': host_match.group('msg') }
        echo_observed = { 'srcaddr': host_match.group('srcaddr'),
                         'srcport': host_match.group('srcport'),
                         'msg': host_match.group('msg') }
        if hostname != 'b':
            sys.stderr.write('Echo message was expected at b, not %s\n' % \
                    hostname)
            return False
        elif echo_observed != echo_correct:
            sys.stderr.write('Echo message malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(echo_correct), json.dumps(echo_observed)))
            return False
        else:
            pass

        if not observations:
            sys.stderr.write('Expected UDP message arriving at a\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_UDP_MSG_RE.search(msg)
        if host2_match is None:
            sys.stderr.write('Expected UDP message arriving at a or c\n')
            return False
        host2_correct = { 'dstaddr': host_match.group('dstaddr'),
                'srcaddr': host_match.group('srcaddr'),
                'dstport': host_match.group('dstport'),
                'srcport': host_match.group('srcport'),
                'msg': host_match.group('msg') }
        host2_observed = { 'dstaddr': host2_match.group('srcaddr'),
                'srcaddr': host2_match.group('dstaddr'),
                'dstport': host2_match.group('srcport'),
                'srcport': host2_match.group('dstport'),
                'msg': host2_match.group('msg') }
        if hostname not in ('a', 'c'):
            sys.stderr.write('UDP message was expected at a or c, not %s\n' % \
                    hostname)
            return False
        elif host2_observed != host2_correct:
            sys.stderr.write('UDP message malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host2_correct), json.dumps(host2_observed)))
            return False
        else:
            pass

        if not observations:
            sys.stderr.write('Expected netcat UDP message arriving at a or c\n')
            return False
        cat, hostname, msg = observations.pop(0)
        netcat2_match = self.NETCAT_MSG_RE.search(msg)
        if netcat2_match is None:
            sys.stderr.write('Expected netcat UDP message arriving at a or c\n')
            return False
        netcat2_correct = { 'addr': host2_match.group('srcaddr'),
                           'port': host2_match.group('srcport'),
                           'msg': host2_match.group('msg') }
        netcat2_observed = { 'addr': netcat2_match.group('addr'),
                           'port': netcat2_match.group('port'),
                           'msg': netcat2_match.group('msg') }
        if hostname not in ('a', 'c'):
            sys.stderr.write('Netcat UDP message was expected at a or c, not %s\n' % \
                    hostname)
            return False
        elif host2_observed != host2_correct:
            sys.stderr.write('Netcat UDP message malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(netcat2_correct), json.dumps(netcat2_observed)))
            return False
        else:
            pass

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
            sys.stderr.write('Expected SYN packet arriving at b\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected SYN packet arriving at b\n')
            return False
        if hostname != 'b':
            sys.stderr.write('SYN packet was expected at b, not %s\n' % \
                    hostname)
            return False
        elif host_match.group('flags') not in ('S', 'A'):
            sys.stderr.write('SYN flags incorrect:\nExpected: %s\nReceived: %s\n' % \
                    ('S or A', host_match.group('flags')))
            return False
        else:
             pass

        # The next packet is optional
        if not observations:
            return True

        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if host2_match is None:
            sys.stderr.write('Expected an SYN RST packet at a or c, if anything.\n')
            return False
        host2_correct = { 
                        'srcport': host_match.group('srcaddr'),
                        'dstport': host_match.group('dstaddr'),
                        'srcaddr': host_match.group('srcport'),
                        'dstaddr': host_match.group('dstport'),
                        'flags': 'R' }
        host2_observed = {
                'srcport': host2_match.group('srcport'),
                'dstport': host2_match.group('dstport'),
                'srcaddr': host2_match.group('srcaddr'),
                'dstaddr': host2_match.group('dstaddr'),
                'flags': host2_match.group('flags'),
                }
        if hostname not in ('a', 'c'):
            sys.stderr.write('SYN RST was expected at host a or c, not %s\n' % \
                    hostname)
        elif host2_observed != host2_correct:
            sys.stderr.write('SYN RST malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host2_correct), json.dumps(host2_observed)))
        else:
            sys.stderr.write('Extra credit for TCP RST\n')

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def blank(self, iteration, time_seen, observations):
        return None

    def new_connection(self, iteration, time_seen, observations):
        if not observations:
            sys.stderr.write('Expected SYN packet arriving at b"\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected SYN packet arriving at b\n')
            return False
        if hostname != 'b':
            sys.stderr.write('SYN packet was expected at b, not %s\n' % \
                    hostname)
            return False
        elif host_match.group('flags') != 'S':
            sys.stderr.write('SYN flags incorrect:\nExpected: %s\nReceived: %s\n' % \
                    ('S', host_match.group('flags')))
            return False
        else:
             pass

        if not observations:
            sys.stderr.write('Expected SYNACK packet arriving at a\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if host2_match is None:
            sys.stderr.write('Expected SYNACK packet arriving at a\n')
            return False
        host2_correct = {
                'srcport': host_match.group('dstport'),
                'dstport': host_match.group('srcport'),
                'srcaddr': host_match.group('dstaddr'),
                'dstaddr': host_match.group('srcaddr'),
                'ack': int(host_match.group('seq')) + 1,
                'flags': 'SA' }
        host2_observed = {
                'srcport': host2_match.group('srcport'),
                'dstport': host2_match.group('dstport'),
                'srcaddr': host2_match.group('srcaddr'),
                'dstaddr': host2_match.group('dstaddr'),
                'ack': int(host2_match.group('ack')),
                'flags': host2_match.group('flags') }
        if hostname not in ('a', 'c'):
            sys.stderr.write('SYN packet was expected at a or c, not %s\n' % \
                    hostname)
            return False
        elif host2_observed != host2_correct:
            sys.stderr.write('SYN packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host2_correct), json.dumps(host2_observed)))
            return False
        else:
            pass

        if not observations:
            sys.stderr.write('Expected ACK packet arriving at b\n')
            return False
        cat, hostname, msg = observations.pop(0)
        host3_match = self.HOST_TCP_MSG_RE.search(msg)
        if host3_match is None:
            sys.stderr.write('Expected ACK packet arriving at b\n')
            return False
        host3_correct = {
                'srcport': host_match.group('srcport'),
                'dstport': host_match.group('dstport'),
                'srcaddr': host_match.group('srcaddr'),
                'dstaddr': host_match.group('dstaddr'),
                'ack': int(host2_match.group('seq')) + 1,
                'seq': int(host_match.group('seq')) + 1,
                'flags': 'A' }
        host3_observed = {
                'srcport': host3_match.group('srcport'),
                'dstport': host3_match.group('dstport'),
                'srcaddr': host3_match.group('srcaddr'),
                'dstaddr': host3_match.group('dstaddr'),
                'ack': int(host3_match.group('ack')),
                'seq': int(host3_match.group('seq')),
                'flags': host3_match.group('flags') }
        if hostname != 'b':
            sys.stderr.write('ACK packet was expected at b, not %s\n' % \
                    hostname)
            return False
        elif host3_observed != host3_correct:
            sys.stderr.write('ACK packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host3_correct), json.dumps(host3_observed)))
            return False
        else:
            pass

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
