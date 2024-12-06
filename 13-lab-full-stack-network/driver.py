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

class Lab6Tester:
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

class Scenario5(Lab6Tester):
    cmd = ['cougarnet', '--stop=20', '--disable-ipv6',
            '--terminal=none', 'scenario5.cfg']

    TCP_MSG_STR = r'TCP packet \((?P<srcaddr>\d+\.\d+\.\d+\.\d+):(?P<srcport>\d+) -> (?P<dstaddr>\d+\.\d+\.\d+\.\d+):(?P<dstport>\d+)\)\s+Flags: (?P<flags>[A-Z]+), Seq=(?P<seq>\d+), Ack=(?P<ack>\d+), Data=(?P<data>.*)'

    HOST_TCP_MSG_RE = re.compile(r'^Received ' + TCP_MSG_STR + '$')

    def __init__(self):
        super()
        self.eval_count = 0
        self.seq = {}
        self.participants = [
                ('', ''),
                ('a', 'd'),
                ('a', 'd'),
                ('b', 'd'),
                ('b', 'd'),
                ('a', 'd'),
                ('b', 'd'),
                ]
        self.eval_mapping = [
                self.blank,
                self.new_connection,
                self.echo_data,
                self.new_connection,
                self.echo_data,
                self.echo_data,
                self.echo_data,
                ]

    def blank(self, iteration, time_seen, observations, participants):
        return None

    def new_connection(self, iteration, time_seen, observations, participants):
        if not observations:
            sys.stderr.write('Expected SYN packet arriving at %s"\n' % (participants[1]))
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected SYN packet arriving at %s\n' % (participants[1]))
            return False
        if hostname != participants[1]:
            sys.stderr.write('SYN packet was expected at %s, not %s\n' % \
                    (participants[1], hostname))
            return False
        elif host_match.group('flags') != 'S':
            sys.stderr.write('SYN flags incorrect:\nExpected: %s\nReceived: %s\n' % \
                    ('S', host_match.group('flags')))
            return False
        else:
             pass

        if not observations:
            sys.stderr.write('Expected SYNACK packet arriving at %s\n' % participants[0])
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if host2_match is None:
            sys.stderr.write('Expected SYNACK packet arriving at %s\n' % participants[0])
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
        if hostname != participants[0]:
            sys.stderr.write('SYNACK packet was expected at %s, not %s\n' % \
                     (participants[0], hostname))
            return False
        elif host2_observed != host2_correct:
            sys.stderr.write('SYNACK packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host2_correct), json.dumps(host2_observed)))
            return False
        else:
            pass

        if not observations:
            sys.stderr.write('Expected ACK packet arriving at %s\n' % participants[1])
            return False
        cat, hostname, msg = observations.pop(0)
        host3_match = self.HOST_TCP_MSG_RE.search(msg)
        if host3_match is None:
            sys.stderr.write('Expected ACK packet arriving at %s\n' % participants[1])
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
        if hostname != participants[1]:
            sys.stderr.write('ACK packet was expected at %s, not %s\n' % \
                    (participants[1], hostname))
            return False
        elif host3_observed != host3_correct:
            sys.stderr.write('ACK packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host3_correct), json.dumps(host3_observed)))
            return False
        else:
            pass

        if participants not in self.seq:
            self.seq[participants] = {}

        key = (host3_correct['srcport'], host3_correct['dstport'],
               host3_correct['srcaddr'], host3_correct['dstaddr'])
        if key not in self.seq[participants]:
            self.seq[participants][key] = [host3_correct['seq'], host3_correct['ack']]

        if observations:
            sys.stderr.write('Expected no further packets"\n')
            return False

        return True

    def echo_data(self, iteration, time_seen, observations, participants, forward=True):
        if forward:
            origin = 0
            destination = 1
            origin_str = 'src'
            destination_str = 'dst'
            key_order = (0, 1, 2, 3)
        else:
            origin = 1
            destination = 0
            origin_str = 'dst'
            destination_str = 'src'
            key_order = (1, 0, 3, 2)

        if not observations:
            sys.stderr.write('Expected data packet arriving at %s"\n' % (participants[destination]))
            return False
        cat, hostname, msg = observations.pop(0)
        host_match = self.HOST_TCP_MSG_RE.search(msg)
        if host_match is None:
            sys.stderr.write('Expected data packet arriving at %s\n' % (participants[destination]))
            return False
        if hostname != participants[destination]:
            sys.stderr.write('Data packet was expected at %s, not %s\n' % \
                    (participants[destination], hostname))
            return False
        else:
             pass

        key = (host_match.group(f'{origin_str}port'), host_match.group(f'{destination_str}port'),
               host_match.group(f'{origin_str}addr'), host_match.group(f'{destination_str}addr'))
        if participants not in self.seq or \
                key not in self.seq[participants]:
            sys.stderr.write('TCP packet does not match any existing connections!\n')
            sys.stderr.write('  %s\n' % str(key))
            return False

        host_correct = {
                'srcport': key[key_order[0]],
                'dstport': key[key_order[1]],
                'srcaddr': key[key_order[2]],
                'dstaddr': key[key_order[3]],
                'seq': self.seq[participants][key][origin] }
        host_observed = {
                'srcport': host_match.group('srcport'),
                'dstport': host_match.group('dstport'),
                'srcaddr': host_match.group('srcaddr'),
                'dstaddr': host_match.group('dstaddr'),
                'seq': int(host_match.group('seq')) }
        if hostname != participants[destination]:
            sys.stderr.write('Data packet was expected at %s, not %s\n' % \
                     (participants[destination], hostname))
            return False
        elif host_observed != host_correct:
            sys.stderr.write('Data packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host_correct), json.dumps(host_observed)))
            return False
        else:
            pass

        self.seq[participants][key][origin] += len(host_match.group('data'))

        if not observations:
            sys.stderr.write('Expected ACK packet arriving at %s"\n' % (participants[origin]))
            return False
        cat, hostname, msg = observations.pop(0)
        host2_match = self.HOST_TCP_MSG_RE.search(msg)
        if host2_match is None:
            sys.stderr.write('Expected ACK packet arriving at %s\n' % (participants[origin]))
            return False
        if hostname != participants[origin]:
            sys.stderr.write('ACK packet was expected at %s, not %s\n' % \
                    (participants[origin], hostname))
            return False
        else:
             pass

        host2_correct = {
                'srcport': key[key_order[1]],
                'dstport': key[key_order[0]],
                'srcaddr': key[key_order[3]],
                'dstaddr': key[key_order[2]],
                'seq': self.seq[participants][key][destination],
                'ack': self.seq[participants][key][origin],
                }
        host2_observed = {
                'srcport': host2_match.group('srcport'),
                'dstport': host2_match.group('dstport'),
                'srcaddr': host2_match.group('srcaddr'),
                'dstaddr': host2_match.group('dstaddr'),
                'seq': int(host2_match.group('seq')),
                'ack': int(host2_match.group('ack')) }
        if hostname != participants[origin]:
            sys.stderr.write('ACK packet was expected at %s, not %s\n' % \
                     (participants[origin], hostname))
            return False
        elif host2_observed != host2_correct:
            sys.stderr.write('ACK packet malformed:\nExpected: %s\nReceived: %s\n' % \
                    (json.dumps(host2_correct), json.dumps(host2_observed)))
            return False
        else:
            pass

        if forward:
            ret = self.echo_data(iteration, time_seen, observations, participants, forward=False)
            if not ret:
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
        return self.eval_mapping[curr](iteration, time_seen, observations,
                                       self.participants[curr])
                            
def main():
    try:
        for scenario in Scenario5,:
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
