import os
import pyshark
import yara
import datetime
from datetime import datetime
import json
import argparse
import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import logging

rule1_path='/home/kali/Desktop/OT-kali/YARA/rules/read_coils.yar'
rule2_path='/home/kali/Desktop/OT-kali/YARA/rules/write_single_coil.yar'
rules = yara.compile(filepaths={
    'namespace1': rule1_path,
    'namespace2': rule2_path
    })

elk_pass = os.getenv('ELASTIC_PASSWORD')
url = "https://132.72.48.18:9200/packets_report/_doc?pipeline=add_date"
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, filename="/var/log/OT/packet_cap.log", filemode="w", format='%(asctime)s - %(levelname)s - %(message)s')

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
    packet_info = {
        "timestamp": timestamp,
        "src_ip": f'{packet.ip.src}',
        "src_port": f'{packet.tcp.srcport}',
        "dst_ip": f'{packet.ip.dst}',
        "dst_port": f'{packet.tcp.dstport}',
        "matching_rule": f'{match}'
     }
    print(packet_info) 
    post_to_elastic(packet_info)
    

def post_to_elastic(payload):
	response = requests.post(
		url,
		auth=HTTPBasicAuth('elastic', elk_pass),
		headers={'Content-Type': 'application/json'},
		json=payload,
		verify=False
	)
	if response.status_code not in [200,201]:
		logging.error(f"Error: Received status code {response.status_code}")
	else:
		logging.info(f"Info: Received status code {response.status_code}")


def main():
    parser = argparse.ArgumentParser(description="Adi")
    parser.add_argument('--port',type=int,default=502)
    args = parser.parse_args()
    interface = 'eth1'
    bpf_filter = f'tcp port {args.port}'
    capture_packets(interface,bpf_filter,args.port)

if __name__ == '__main__':
    main()




