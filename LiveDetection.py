# Wireless Signal Intrusion Detection

from scapy.all import *
from Detector import Detector
from Detector import normalize

cnt = 0
detector = Detector()


# Capture and save as a pacp file
def live_capture(channel, duration_time):
    os.popen("airport -z").read()
    os.popen("airport --channel=%s" % channel).read()
    os.popen("tshark -a duration:%s -b duration:1 -I -i en0 -n -w /tmp/capture/capture.pcap -F pcap" %
             duration_time).read()
    return "/tmp/capture.pcap"


# Parsing
def parse(frame):
    global cnt
    global detector
    if frame.haslayer(Dot11):  # 802.11 frame
        cnt = cnt + 1
        if frame.type == 0 and (frame.subtype == 11 or frame.subtype == 12):  # Auth/Deauth frame
            vector = normalize(frame)
            result = detector.detect(vector)
            if result[0][0] > 0.5 and result[0][1] < 0.5 and result[0][2] < 0.5:
                print("No." + str(cnt), "Authentication attack detected!")
                # print(frame.show())
                print("---------------------------------------------")
            elif result[0][0] < 0.5 and result[0][1] > 0.5 and result[0][2] < 0.5:
                print("No." + str(cnt), "Deauthentication attack detected!")
                # print(frame.show())
                print("---------------------------------------------")


if __name__ == '__main__':
    # file_path = live_capture(channel=9, duration_time=15)  # Require permission
    # sniff(offline="/tmp/capture_chan9.pcap", prn=parse)
    sniff(offline="./auth.pcap", prn=parse)
