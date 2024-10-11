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

NEXT_ITERATION_SLACK = 0.15 # 150 ms
MAX_INTERVAL = 0.5 # 500 ms
INTERVAL = 1.0

class Lab3Tester:
    cmd = []
    expected_observations = []

    def evaluate(self, iteration, time_seen, observations):
        if iteration >= len(self.expected_observations):
            # not evaluated
            return None

        solution = self.expected_observations[iteration]
        if solution is None:
            # not evaluated
            return None

        i = 0
        for expected_cat, expected_hostnames in solution:
            observed_hostnames = []
            num_hostnames = len(expected_hostnames)
            j = i
            for j in range(i, i + num_hostnames):
                if j >= len(observations):
                    break
                observed_cat, observed_hostname = observations[j]
                if observed_cat != expected_cat:
                    sys.stderr.write(('ERROR: Time %0.3f: ' + \
                            'Expected %d %s at %s, but observed %s at %s\n') % \
                            (time_seen, num_hostnames, expected_cat,
                                ', '.join(expected_hostnames),
                                observed_cat, observed_hostname))
                    return False
                observed_hostnames.append(observed_hostname)
            j += 1
            i = j

            expected_hostnames = sorted(expected_hostnames)
            observed_hostnames = sorted(observed_hostnames)
            if expected_hostnames != observed_hostnames:
                sys.stderr.write(('ERROR: Time %0.3f: ' + \
                        'Expected %s at %s, but observed %s at %s\n') % \
                        (time_seen, expected_cat,
                            ', '.join(expected_hostnames),
                            expected_cat, ', '.join(observed_hostnames)))
                return False

        if len(observations) > j:
            sys.stderr.write(('ERROR: Time %0.3f: ' + \
                    'Unexpected %s at %s\n') % \
                    (time_seen, observations[j][0], observations[j][1]))
            return False

        return True

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

            if m is not None:
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

                observations.append((cat, hostname))

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

class Scenario1(Lab3Tester):
    cmd = ['cougarnet', '--stop=14', '--disable-ipv6',
            '--terminal=none', 'scenario1.cfg']

    expected_observations = [
            [('ICMP', ['r2']),
                ('ICMP', ['r3']),
                ('ICMP', ['r4']),
                ('ICMP', ['r5']),
                ('ICMP', ['r4']),
                ('ICMP', ['r3']),
                ('ICMP', ['r2']),
                ('ICMP', ['r1'])],
            [('ICMP', ['r3']),
                ('ICMP', ['r4']),
                ('ICMP', ['r3']),
                ('ICMP', ['r2'])],
            ]

class Scenario2(Lab3Tester):
    cmd = ['cougarnet', '--stop=25', '--disable-ipv6',
            '--terminal=none', 'scenario2.cfg']

    expected_observations = [
            [('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r2'])],
            [('ICMP', ['r3']),
                ('ICMP', ['r4']),
                ('ICMP', ['r3']),
                ('ICMP', ['r2'])],
            None,
            None,
            None,
            None,
            None,
            None,
            [('ICMP', ['r3']),
                ('ICMP', ['r4']),
                ('ICMP', ['r5']),
                ('ICMP', ['r6']),
                ('ICMP', ['r5']),
                ('ICMP', ['r4']),
                ('ICMP', ['r3']),
                ('ICMP', ['r2'])],
            [('ICMP', ['r3']),
                ('ICMP', ['r4']),
                ('ICMP', ['r3']),
                ('ICMP', ['r2'])],
            ]

class Scenario3(Lab3Tester):
    cmd = ['cougarnet', '--stop=42', '--disable-ipv6',
            '--terminal=none', 'scenario3.cfg']

    expected_observations = [
            [('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r4']),
                ('ICMP', ['r10']),
                ('ICMP', ['r4']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r9'])],
            [('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r11']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r9'])],
            [('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r4']),
                ('ICMP', ['r5']),
                ('ICMP', ['r12']),
                ('ICMP', ['r5']),
                ('ICMP', ['r4']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r9'])],
            [('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r4']),
                ('ICMP', ['r5']),
                ('ICMP', ['r13']),
                ('ICMP', ['r5']),
                ('ICMP', ['r4']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r9'])],
            [('ICMP', ['r1']),
                ('ICMP', ['r2']),
                ('ICMP', ['r14']),
                ('ICMP', ['r15']),
                ('ICMP', ['r14']),
                ('ICMP', ['r2']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6'])],
            [('ICMP', ['r8']),
                ('ICMP', ['r2']),
                ('ICMP', ['r14']),
                ('ICMP', ['r15']),
                ('ICMP', ['r14']),
                ('ICMP', ['r2']),
                ('ICMP', ['r8']),
                ('ICMP', ['r7'])],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            [('ICMP', ['r6']),
                ('ICMP', ['r1']),
                ('ICMP', ['r2']),
                ('ICMP', ['r14']),
                ('ICMP', ['r15']),
                ('ICMP', ['r14']),
                ('ICMP', ['r2']),
                ('ICMP', ['r1']),
                ('ICMP', ['r6']),
                ('ICMP', ['r7'])],
            ]

def main():
    try:
        for scenario in Scenario1, Scenario2, Scenario3:
            print(f'Running {scenario.__name__}...')
            tester = scenario()
            success, total = tester.run()
            sys.stderr.write(f'  Result: {success}/{total}\n')
    except KeyboardInterrupt:
        sys.stderr.write('Interrupted\n')

if __name__ == '__main__':
    main()
