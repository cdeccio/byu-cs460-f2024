#!/usr/bin/env python3

import os
import re
import signal
import subprocess
import sys

LOG_PREFIX = r'^(?P<time>\d+\.\d+)\s+(?P<hostname>\S+)\s+'
LOG_START_RE = re.compile(LOG_PREFIX + r'START$')
LOG_TCP_STATUS_RE = re.compile(LOG_PREFIX + \
        r'(?P<pct>\d+)% has been (?P<action>sent|recvd|acked)')

class Lab5Tester:
    cmd = []
    maxtime = None
    sha1output = None
    downloads_dir = 'downloads'

    def evaluate(self, lines):
        tcp_status = {}
        starttime = None
        endtime = None
        for line in lines:
            m = LOG_START_RE.search(line)
            if m is not None:
                starttime = float(m.group('time'))
                continue
            m = LOG_TCP_STATUS_RE.search(line)
            if m is None:
                continue
            endtime = float(m.group('time'))
            hostname = m.group('hostname')
            pct = int(m.group('pct'))
            action = m.group('action')

            tcp_status[(hostname, action)] = pct

        if ('a', 'sent') not in tcp_status or tcp_status[('a', 'sent')] != 100:
            sys.stderr.write('a sent only %d%%\n' % tcp_status.get(('a', 'sent'), 0))
            return 0, 1
        if ('a', 'acked') not in tcp_status or tcp_status[('a', 'acked')] != 100:
            sys.stderr.write('a received acks for only %d%%\n' % tcp_status.get(('a', 'acked'), 0))
            return 0, 1
        if ('b', 'recvd') not in tcp_status or tcp_status[('b', 'recvd')] != 100:
            sys.stderr.write('b received only %d%%\n' % tcp_status.get(('b', 'recvd'), 0))
            return 0, 1

        if self.sha1output is not None: 
            try:
                output = subprocess.check_output(['sha1sum',
                                                  os.path.join(self.downloads_dir, self.filename)])
            except subprocess.CalledProcessError as e:
                sys.stderr.write('Problem detecting sha1sum of %s\n' % \
                                                  (os.path.join(self.downloads_dir, self.filename)))
                return 0, 1

            sha1output = output.decode('utf-8').split()[0]
            if sha1output != self.sha1output:
                sys.stderr.write('SHA1 output of %s does not match\n' % \
                        (os.path.join(self.downloads_dir, self.filename)))
                return 0, 1

        duration = endtime - starttime
        if self.maxtime is not None and duration > self.maxtime:
            sys.stderr.write('Expected duration exceeded (%f > %f)\n' % \
                                              (duration, self.maxtime))
            return 0, 1

        sys.stderr.write('Finished in %f seconds (end time: %f)\n' % (duration, endtime))

        return 1, 1

    def run(self):
        sys.stderr.write('running %s\n' % self.cmd)

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
        return self.evaluate(output_lines)

class Scenario1(Lab5Tester):
    cmd = ['cougarnet', '--stop=10', '--terminal=none', '--vars',
           'loss=0,window=10000,file=hello.txt,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'hello.txt'
    sha1output = '22596363b3de40b06f981fb85d82312e8c0ed511'
    maxtime = 5

class Scenario2(Lab5Tester):
    cmd = ['cougarnet', '--stop=10', '--terminal=none', '--vars',
           'loss=0,window=10000,file=test.txt,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'test.txt'
    sha1output = 'e742dc9de5bac34d82117e015f597378a205e5c1'
    maxtime = 5

class Scenario3(Lab5Tester):
    cmd = ['cougarnet', '--stop=25', '--terminal=none', '--vars',
           'loss=0,window=10000,file=byu-y-mtn.jpg,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'byu-y-mtn.jpg'
    sha1output = '6d82cbd6949c0bb89a9071b821bb62ed73a462ff'
    maxtime = 20

class Scenario4(Lab5Tester):
    cmd = ['cougarnet', '--stop=25', '--terminal=none', '--vars',
           'loss=0,window=50000,file=byu-y-mtn.jpg,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'byu-y-mtn.jpg'
    sha1output = '6d82cbd6949c0bb89a9071b821bb62ed73a462ff'
    maxtime = 10

class Scenario5(Lab5Tester):
    cmd = ['cougarnet', '--stop=20', '--terminal=none', '--vars',
           'loss=5,window=10000,file=test.txt,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'test.txt'
    sha1output = 'e742dc9de5bac34d82117e015f597378a205e5c1'
    maxtime = 10

class Scenario6(Lab5Tester):
    cmd = ['cougarnet', '--stop=60', '--terminal=none', '--vars',
           'loss=1,window=50000,file=byu-y-mtn.jpg,fast_retransmit=off',
           'scenario1.cfg']
    filename = 'byu-y-mtn.jpg'
    sha1output = '6d82cbd6949c0bb89a9071b821bb62ed73a462ff'
    maxtime = 50

class Scenario7(Lab5Tester):
    cmd = ['cougarnet', '--stop=10', '--terminal=none', '--vars',
           'loss=5,window=10000,file=test.txt,fast_retransmit=on',
           'scenario1.cfg']
    filename = 'test.txt'
    sha1output = 'e742dc9de5bac34d82117e015f597378a205e5c1'
    maxtime = 5

class Scenario8(Lab5Tester):
    cmd = ['cougarnet', '--stop=25', '--terminal=none', '--vars',
           'loss=1,window=50000,file=byu-y-mtn.jpg,fast_retransmit=on',
           'scenario1.cfg']
    filename = 'byu-y-mtn.jpg'
    sha1output = '6d82cbd6949c0bb89a9071b821bb62ed73a462ff'
    maxtime = 15

def main():
    try:
        for scenario in (Scenario1, Scenario2, Scenario3, Scenario4,
                         Scenario5, Scenario6, Scenario7, Scenario8):
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
