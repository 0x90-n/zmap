#!/usr/bin/python3

import sys

from collections import defaultdict

# Takes the output from:
# sudo ./zmap --probe-module=traceroute --output-fields="target,hop,saddr,sent_sec,sent_usec,timestamp_ts,timestamp_us" -P 30 -O csv -o output.csv


def parse(f):
    traces = defaultdict(dict) # target => {hop => (hop_ip, delta_us) }
    for line in f:
        if line.startswith('target'):
            continue
        target, hop_n, hop_ip, sent_s, sent_us, recv_s, recv_us = line.split(',')

        sent_sec = int(sent_s)
        sent_usec = int(sent_us)

        recv_sec = int(recv_s) & 0xfff
        recv_usec = int(recv_us)

        if (recv_sec < sent_sec):
            recv_sec += 0x1000
        sent_t = sent_sec*1000000 + sent_usec
        recv_t = recv_sec*1000000 + recv_usec
        delta_us = recv_t - sent_t

        tr = traces[target]
        tr[int(hop_n)] = (hop_ip, delta_us)
    return traces

traces = None
if len(sys.argv) > 1:
    fn = sys.argv[1]
    with open(fn, 'r') as f:
        traces = parse(f)
else:
    traces = parse(sys.stdin)



print("%d unique targets" % len(traces.keys()))

count_hops_present = defaultdict(int)

tot = 0
for target, trace in traces.items():
    count_hops = len(trace.keys())
    count_hops_present[count_hops] += 1
    tot += count_hops

avg_hops_present = float(tot) / len(traces)

print('%.3f average hops / trace' % avg_hops_present)


for i in range(min(count_hops_present.keys()),1+max(count_hops_present.keys())):
    print('%d hops: %d' % (i, count_hops_present[i]))
print('==============')

for target, trace in traces.items():
    print("-------------------------")
    print("%s:" % (target))
    for hop in range(min(trace.keys()),1+max(trace.keys())):
        if hop in trace:
            ip, us = trace[hop]
            print(" % 2d  % 15s   %.3fms" % (hop, ip, float(us)/1000))
        else:
            print(" % 2d  *" % (hop))
