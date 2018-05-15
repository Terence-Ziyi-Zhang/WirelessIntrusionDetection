import os

from scapy.all import *


# Capture and save as a pacp file
def live_capture(channel, duration_time):
    os.popen("airport -z").read()
    os.popen("airport --channel=%s" % channel).read()
    os.popen("tshark -a duration:%s -s0 -I -i en0 -f 'not type data' -w /tmp/capture_chan%s.pcap -F pcap" % (
        duration_time, channel)).read()
    return "/tmp/capture_chan%s.pcap" % channel


# Parsing
def parse(frame):
    '''
    addr1: dest
    addr2: src
    addr3: BSSID

    More about Dot11:
    https://stackoverflow.com/questions/30811426/scapy-python-get-802-11-ds-status
    '''
    global cnt
    cnt += 1
    if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 0:
        # Parsing
        print("No.", cnt)
        print("ToDS:", frame.FCfield & 0b1 != 0)
        print("MF", frame.FCfield & 0b10 != 0)
        print("WEP", frame.FCfield & 0b01000000 != 0)
        print("src MAC:", frame.addr2)
        print("dest MAC:", frame.addr1)
        print("BSSID:", frame.addr3)

        print("\n")


if __name__ == '__main__':
    # file_path = live_capture(channel=11, duration_time=10)  # Require permission
    sniff(offline="/tmp/capture_chan11.pcap", prn=parse)
