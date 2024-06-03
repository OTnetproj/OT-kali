import os
import pyshark
import yara
from datetime import datetime
import json
import argparse

rule1_path='/home/kali/Desktop/OT-kali/YARA/rules/read_coils.yar'
rule2_path='/home/kali/Desktop/OT-kali/YARA/rules/write_single_coil.yar'
rules = yara.compile(filepaths={
    'namespace1': rule1_path,
    'namespace2': rule2_path
    })

def capture_packets(interface, bpf_filter,port):
    capture = pyshark.LiveCapture(interface=interface,bpf_filter=bpf_filter, decode_as={f'tcp.port=={port}': 'mbtcp'},use_json=True,include_raw=True)
    print(f"Start capturing packets on interface {interface}, press CTRL+C to stop.")
    try:
        capture.apply_on_packets(packet_callback)
    except:
        print("\nCapture stopped.")
    finally:
        capture.close()


def packet_callback(packet):
    try:
        if packet['MBTCP']:
            packet_bytes = packet.get_raw_packet()
            # match = read_coils_rule.match(data=packet_str)
            match = rules.match(data=packet_bytes)
            if match:
                print(match)
                packet_report(packet,match)
        else:
            print("Packet isn't Modbus type")

    except Exception as e:
        pass

def packet_report(packet,match):
    timestamp = packet.sniff_time.isoformat()
    src_ip = packet.ip.src
    src_port = packet.tcp.srcport
    dst_ip = packet.ip.dst
    dst_port = packet.tcp.dstport

    packet_info = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "matching_rule": match
     }
    print(packet_info)


def main():
    parser = argparse.ArgumentParser(description="Adi")
    parser.add_argument('--port',type=int,default=502)
    args = parser.parse_args()
    interface = 'eth1'
    bpf_filter = f'tcp port {args.port}'
    capture_packets(interface,bpf_filter,args.port)

if __name__ == '__main__':
    main()




