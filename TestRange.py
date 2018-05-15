import os

channel = 11
duration_time = 10

os.popen("airport -z").read()
os.popen("airport --channel=%s" % channel).read()
os.popen("tshark -a duration:%s -s0 -I -i en0 -f 'not type data' -w /tmp/capture_chan%s.pcap -F pcap" % (
    duration_time, channel)).read()
