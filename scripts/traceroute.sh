#!/bin/bash



for i in `seq 150 160`; do

./zmap --probe-module=traceroute --output-fields="target,hop,saddr,sent_sec,sent_usec,timestamp_ts,timestamp_us" -O csv --probe-args="$i" -P 1 -B 500M -n 1% --seed 1234 -o ~/tr/tr.hop$i.out

done
