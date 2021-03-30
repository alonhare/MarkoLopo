import pyshark
import csv

PCUP_FILE = r"C:\Users\alonh\Desktop\sniff.pcapng"
OUTPUT_FILE = r"C:\Users\alonh\Desktop\output.csv"
DISTANCE = "5"


def analyze_capture(cap):
    retry_counter = 0
    all = 0
    for pkt in cap:
        if int(pkt.length) < 1500:
            continue
        all += 1
        if pkt["wlan"].fc_retry == '1':
            retry_counter += 1
    print(retry_counter, all)
    print(100.0 * retry_counter / all)
    return (retry_counter, all)


def get_capture():
    return pyshark.FileCapture(PCUP_FILE)


def write_to_file(retry_counter, all):
    with open(OUTPUT_FILE, mode='a', newline='') as out_file:
        file_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        file_writer.writerow([DISTANCE, all, retry_counter])


for i in range(5):
    cap = get_capture()
    retry_counter, all = analyze_capture(cap)
    write_to_file(retry_counter, all)

print('end of experiment')
