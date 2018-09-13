# Wireless Signal Intrusion Detection

from scapy.all import *
from Detector import Detector
from Detector import normalize

# Global variables
cnt = 0
seq = 0
detector = Detector()


# Capture via Terminal.app
def live_capture(channel, duration_time, buffer_path):
    # os.popen("airport -z")
    os.popen("airport --channel=%s" % channel)
    os.popen("tshark -a duration:%s -b duration:1 -I -i en0 -n -w %scapture.pcap -F pcap" %
             (duration_time, buffer_path))


# modify the sequence number
def modify(seq):
    if len(str(seq)) == 1:
        return "0000" + str(seq)
    elif len(str(seq)) == 2:
        return "000" + str(seq)
    elif len(str(seq)) == 3:
        return "00" + str(seq)
    elif len(str(seq)) == 4:
        return "0" + str(seq)
    elif len(str(seq)) == 5:
        return str(seq)


# Searching for every pcap file in given directory
def search(buffer_path):
    global cnt
    global seq
    cnt = 0
    seq = seq + 1
    status = 0
    for _, _, file_names in os.walk(buffer_path):
        for file_name in file_names:
            if file_name.find(modify(seq)) >= 0:
                status = 1
                print("Sniffing", file_name)
                sniff(offline=buffer_path + file_name, prn=parse)
                print("Sniffing finished. ")
                print("------------------------------------------------------")
    return status


# Parse 802.11 frames
def parse(frame):
    global cnt
    global detector
    if frame.haslayer(Dot11):  # 802.11 frame
        cnt = cnt + 1
        if frame.type == 0 and (frame.subtype == 11 or frame.subtype == 12):  # Auth/Deauth frame
            vector = normalize(frame)
            result = detector.detect(vector)
            if result[0][0] > 0.5 and result[0][1] < 0.5 and result[0][2] < 0.5:
                print("802.11 frame no." + str(
                    cnt) + ":", "Authentication attack detected!", "AP:", frame.addr1, "under attack! ")
            elif result[0][0] < 0.5 and result[0][1] > 0.5 and result[0][2] < 0.5:
                print("802.11 frame no." + str(
                    cnt) + ":", "Deauthentication attack detected!", "AP:", frame.addr2, "under attack!")


def inspect_thread(buffer_path):
    # While sniffing pcap files in main thread
    global seq
    seq = 0
    time.sleep(1)
    print("*** Detection started. ***")
    while 1:
        time.sleep(1)
        if search(buffer_path) == 0:
            print("*** Detection finished. ***")
            break


def activate(CHANNEL, DURATION_TIME, BUFFER_PATH):
    # Ensure the buffer directory
    if os.path.exists(BUFFER_PATH):
        for _, _, file_names in os.walk(BUFFER_PATH):
            for file_name in file_names:
                os.remove(BUFFER_PATH + file_name)
    else:
        os.makedirs(BUFFER_PATH)

    # Capture frames in a branch thread
    cap_thread = threading.Thread(target=live_capture, args=(CHANNEL, DURATION_TIME, BUFFER_PATH))
    ins_thread = threading.Thread(target=inspect_thread, args=(BUFFER_PATH,))
    cap_thread.start()
    ins_thread.start()


if __name__ == '__main__':
    # activate(CHANNEL="9", DURATION_TIME="5", BUFFER_PATH="/tmp/capture/")
    sniff(offline="./Auth_1.pcap", prn=parse)
