'''!!!Running this script will change the existing files!!!'''

import os
from glob import glob
from concurrent.futures import ProcessPoolExecutor

import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import tqdm
from nfstream import NFStreamer, NFPlugin

BENIGN_PATH = '/mnt/data/All Datasets/data/Benign'
MALWARE_PATH = '/mnt/data/All Datasets/data/Malware'
INTRUSION_PATH = '/mnt/data/All Datasets/raw_data/Intrusion'

benign_files = [y for x in os.walk(BENIGN_PATH) for y in glob(os.path.join(x[0], '*.pcap'))]
malware_files = [y for x in os.walk(MALWARE_PATH) for y in glob(os.path.join(x[0], '*.pcap'))]
intrusion_files = [y for x in os.walk(INTRUSION_PATH) for y in glob(os.path.join(x[0], '*.pcap'))]

import os
import pickle

import pandas as pd

from nfstream import NFStreamer, NFPlugin
from nfstream.anonymizer import NFAnonymizer
from nfstream.utils import validate_flows_per_file, csv_converter, open_file

class PacketStore(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.ip_packets = [packet.ip_packet]
        flow.udps.src_port = packet.src_port
        flow.udps.dst_port = packet.dst_port
        flow.udps.protocol = packet.protocol
        flow.udps.src2dst_raw_size_arr = [-1]*self.n
        flow.udps.src2dst_raw_size_arr[0] = packet.raw_size
        flow.udps.src2dst_raw_size = 0
        flow.udps.dst2src_raw_size_arr = [-1]*self.n
        flow.udps.dst2src_raw_size = 0

        flow.udps.src2dst_ip_size_arr = [-1]*self.n
        flow.udps.src2dst_ip_size_arr[0] = packet.ip_size
        flow.udps.src2dst_ip_size = 0
        flow.udps.dst2src_ip_size_arr = [-1]*self.n
        flow.udps.dst2src_ip_size = 0

        flow.udps.src2dst_transport_size_arr = [-1]*self.n
        flow.udps.src2dst_transport_size_arr[0] = packet.transport_size
        flow.udps.src2dst_transport_size = 0
        flow.udps.dst2src_transport_size_arr = [-1]*self.n
        flow.udps.dst2src_transport_size = 0

        flow.udps.src2dst_payload_size_arr = [-1]*self.n
        flow.udps.src2dst_payload_size_arr[0] = packet.payload_size
        flow.udps.src2dst_payload_size = 0
        flow.udps.dst2src_payload_size_arr = [-1]*self.n
        flow.udps.dst2src_payload_size = 0

        flow.udps.src2dst_total_packet_size_arr = [-1]*self.n
        total_ps = packet.raw_size + packet.ip_size + packet.transport_size + packet.payload_size
        flow.udps.src2dst_total_packet_size_arr[0] = total_ps
        flow.udps.src2dst_total_packet_size = 0
        flow.udps.dst2src_total_packet_size_arr = [-1]*self.n
        flow.udps.dst2src_total_packet_size = 0

        flow.udps.src2dst_max_ps = 0
        flow.udps.dst2src_max_ps = 0
        flow.udps.src2dst_min_ps = 0
        flow.udps.dst2src_min_ps = 0
        flow.udps.src2dst_mean_ps = 0
        flow.udps.dst2src_mean_ps = 0
        flow.udps.src2dst_std_ps = 0
        flow.udps.dst2src_std_ps = 0

        flow.udps.src2dst_syn_count = 0
        flow.udps.dst2src_syn_count = 0

        flow.udps.src2dst_ece_count = 0
        flow.udps.dst2src_ece_count = 0

        flow.udps.src2dst_cwr_count = 0
        flow.udps.dst2src_cwr_count = 0

        flow.udps.src2dst_urg_count = 0
        flow.udps.dst2src_urg_count = 0

        flow.udps.src2dst_ack_count = 0
        flow.udps.dst2src_ack_count = 0

        flow.udps.src2dst_psh_count = 0
        flow.udps.dst2src_psh_count = 0

        flow.udps.src2dst_rst_count = 0
        flow.udps.dst2src_rst_count = 0

        flow.udps.src2dst_fin_count = 0
        flow.udps.dst2src_fin_count = 0

        flow.udps.src2dst_piat_ms = [-1] * self.n
        flow.udps.src2dst_piat_ms[0] = packet.delta_time

        flow.udps.dst2src_piat_ms = [-1] * self.n

        flow.udps.src2dst_piat_mean_ms = 0.0
        flow.udps.dst2src_piat_mean_ms = 0.0

        flow.udps.src2dst_piat_min_ms = 0
        flow.udps.dst2src_piat_min_ms = 0

        flow.udps.src2dst_piat_max_ms = 0
        flow.udps.dst2src_piat_max_ms = 0

        flow.udps.src2dst_piat_std_ms = 0.0
        flow.udps.dst2src_piat_std_ms = 0.0
    
    def on_update(self, packet, flow):
        flow.udps.ip_packets.append(packet.ip_packet)
        if flow.bidirectional_packets <= self.n:
            packet_index = flow.bidirectional_packets - 1
            if packet.direction == 0:
                flow.udps.src2dst_raw_size_arr[packet_index] = packet.raw_size
                flow.udps.src2dst_ip_size_arr[packet_index] = packet.ip_size
                flow.udps.src2dst_transport_size_arr[packet_index] = packet.transport_size
                flow.udps.src2dst_payload_size_arr[packet_index] = packet.payload_size
                total_ps = packet.raw_size + packet.ip_size + packet.transport_size + packet.payload_size
                flow.udps.src2dst_total_packet_size_arr[packet_index] = total_ps

                flow.udps.src2dst_piat_ms[packet_index] = packet.delta_time

                if packet.syn == True:
                    flow.udps.src2dst_syn_count += 1

                if packet.cwr == True:
                    flow.udps.src2dst_cwr_count += 1

                if packet.ece == True:
                    flow.udps.src2dst_ece_count += 1

                if packet.urg == True:
                    flow.udps.src2dst_urg_count += 1

                if packet.ack == True:
                    flow.udps.src2dst_ack_count += 1

                if packet.psh == True:
                    flow.udps.src2dst_psh_count += 1

                if packet.rst == True:
                    flow.udps.src2dst_rst_count += 1

                if packet.fin == True:
                    flow.udps.src2dst_fin_count += 1
            else:
                flow.udps.dst2src_raw_size_arr[packet_index] = packet.raw_size
                flow.udps.dst2src_ip_size_arr[packet_index] = packet.ip_size
                flow.udps.dst2src_transport_size_arr[packet_index] = packet.transport_size
                flow.udps.dst2src_payload_size_arr[packet_index] = packet.payload_size
                total_ps = packet.raw_size + packet.ip_size + packet.transport_size + packet.payload_size
                flow.udps.dst2src_total_packet_size_arr[packet_index] = total_ps

                flow.udps.dst2src_piat_ms[packet_index] = packet.delta_time

                if packet.syn == True:
                    flow.udps.dst2src_syn_count += 1

                if packet.cwr == True:
                    flow.udps.dst2src_cwr_count += 1

                if packet.ece == True:
                    flow.udps.dst2src_ece_count += 1

                if packet.urg == True:
                    flow.udps.dst2src_urg_count += 1

                if packet.ack == True:
                    flow.udps.dst2src_ack_count += 1

                if packet.psh == True:
                    flow.udps.dst2src_psh_count += 1

                if packet.rst == True:
                    flow.udps.dst2src_rst_count += 1

                if packet.fin == True:
                    flow.udps.dst2src_fin_count += 1

    def on_expire(self, flow):
        src2dst_raw_size = np.array(flow.udps.src2dst_raw_size_arr)
        src2dst_raw_size_refined = src2dst_raw_size[src2dst_raw_size!=-1]
        if src2dst_raw_size_refined.shape[0]:
            flow.udps.src2dst_raw_size = np.sum(src2dst_raw_size_refined)

        dst2src_raw_size = np.array(flow.udps.dst2src_raw_size_arr)
        dst2src_raw_size_refined = dst2src_raw_size[dst2src_raw_size!=-1]
        if dst2src_raw_size_refined.shape[0]:
            flow.udps.dst2src_raw_size = np.sum(dst2src_raw_size_refined)

        src2dst_ip_size = np.array(flow.udps.src2dst_ip_size_arr)
        src2dst_ip_size_refined = src2dst_ip_size[src2dst_ip_size!=-1]
        if src2dst_ip_size_refined.shape[0]:
            flow.udps.src2dst_ip_size = np.sum(src2dst_ip_size_refined)

        dst2src_ip_size = np.array(flow.udps.dst2src_ip_size_arr)
        dst2src_ip_size_refined = dst2src_ip_size[dst2src_ip_size!=-1]
        if dst2src_ip_size_refined.shape[0]:
            flow.udps.dst2src_ip_size = np.sum(dst2src_ip_size_refined)

        src2dst_transport_size = np.array(flow.udps.src2dst_transport_size_arr)
        src2dst_transport_size_refined = src2dst_transport_size[src2dst_transport_size!=-1]
        if src2dst_transport_size_refined.shape[0]:
            flow.udps.src2dst_transport_size = np.sum(src2dst_transport_size_refined)

        dst2src_transport_size = np.array(flow.udps.dst2src_transport_size_arr)
        dst2src_transport_size_refined = dst2src_transport_size[dst2src_transport_size!=-1]
        if dst2src_transport_size_refined.shape[0]:
            flow.udps.dst2src_transport_size = np.sum(dst2src_transport_size_refined)

        src2dst_payload_size = np.array(flow.udps.src2dst_payload_size_arr)
        src2dst_payload_size_refined = src2dst_payload_size[src2dst_payload_size!=-1]
        if src2dst_payload_size_refined.shape[0]:
            flow.udps.src2dst_payload_size = np.sum(src2dst_payload_size_refined)

        dst2src_payload_size = np.array(flow.udps.dst2src_payload_size_arr)
        dst2src_payload_size_refined = dst2src_payload_size[dst2src_payload_size!=-1]
        if dst2src_payload_size_refined.shape[0]:
            flow.udps.dst2src_payload_size = np.sum(dst2src_payload_size_refined)

        src2dst_total_packet_size = np.array(flow.udps.src2dst_total_packet_size_arr)
        src2dst_total_packet_size_refined = src2dst_total_packet_size[src2dst_total_packet_size!=-1]
        if src2dst_total_packet_size_refined.shape[0]:
            flow.udps.src2dst_total_packet_size = np.sum(src2dst_total_packet_size_refined)
            flow.udps.src2dst_min_ps = np.min(src2dst_total_packet_size_refined)
            flow.udps.src2dst_max_ps = np.max(src2dst_total_packet_size_refined)
            flow.udps.src2dst_mean_ps = np.mean(src2dst_total_packet_size_refined)
            flow.udps.src2dst_std_ps = np.std(src2dst_total_packet_size_refined)

        dst2src_total_packet_size = np.array(flow.udps.dst2src_total_packet_size_arr)
        dst2src_total_packet_size_refined = dst2src_total_packet_size[dst2src_total_packet_size!=-1]
        if dst2src_total_packet_size_refined.shape[0]:
            flow.udps.dst2src_total_packet_size = np.sum(dst2src_total_packet_size_refined)
            flow.udps.dst2src_min_ps = np.min(dst2src_total_packet_size_refined)
            flow.udps.dst2src_max_ps = np.max(dst2src_total_packet_size_refined)
            flow.udps.dst2src_mean_ps = np.mean(dst2src_total_packet_size_refined)
            flow.udps.dst2src_std_ps = np.std(dst2src_total_packet_size_refined)

        src2dst_piat_ms = np.array(flow.udps.src2dst_piat_ms)
        src2dst_piat_ms_refined = src2dst_piat_ms[src2dst_piat_ms!=-1]
        if src2dst_piat_ms_refined.shape[0]:
            flow.udps.src2dst_piat_mean_ms = np.mean(src2dst_piat_ms_refined)
            flow.udps.src2dst_piat_min_ms = np.min(src2dst_piat_ms_refined)
            flow.udps.src2dst_piat_max_ms = np.max(src2dst_piat_ms_refined)
            flow.udps.src2dst_piat_std_ms = np.std(src2dst_piat_ms_refined)

        dst2src_piat_ms = np.array(flow.udps.dst2src_piat_ms)
        dst2src_piat_ms_refined = dst2src_piat_ms[dst2src_piat_ms!=-1]
        if dst2src_piat_ms_refined.shape[0]:
            flow.udps.dst2src_piat_mean_ms = np.mean(dst2src_piat_ms_refined)
            flow.udps.dst2src_piat_min_ms = np.min(dst2src_piat_ms_refined)
            flow.udps.dst2src_piat_max_ms = np.max(dst2src_piat_ms_refined)
            flow.udps.dst2src_piat_std_ms = np.std(dst2src_piat_ms_refined)


def dump_ip_packets(flow, output_sessions_path):
    application_category_name = '_'.join(flow.application_category_name.split('-'))
    application_name = '_'.join(flow.application_name.split('-'))
    
    pckt_filename =         '-'.join([str(flow.id), flow.src_ip, str(flow.src_port), flow.dst_ip, str(flow.dst_port), str(flow.protocol), application_category_name, application_name])

    output_path = os.path.join(output_sessions_path, pckt_filename)
    ip_packet_list = flow.udps.ip_packets

    with open(output_path, 'wb') as f_bytes:
        pickle.dump(ip_packet_list, f_bytes)


def get_output_paths(src_pcap_path, output_dir):
    *_, dataset, pcap_name = src_pcap_path.split('/')
    output_folder = os.path.join(output_dir, dataset, pcap_name.split('.pcap')[0])
    output_sessions_folder = os.path.join(output_folder, 'sessions_8')
    os.makedirs(output_sessions_folder, exist_ok=True)
    return output_folder, output_sessions_folder


class DataStorageMode:
    feature_only = 0
    ip_packet_only = 1
    both_packet_feature = 2
    
    
class CustomStreamer(NFStreamer):
    def dump(self, output_dir, n_packets=20, store_mode=DataStorageMode.feature_only):
            
        output_folder, output_sessions_folder = get_output_paths(self.source, output_dir)
        
        CSV_NAME = str(n_packets)
        
        output_csv_path = os.path.join(output_folder, f'{CSV_NAME}.csv')
        if not os.path.isfile(output_csv_path):
            write_header = True
            ip_packet_idx = None

            with open(output_csv_path, 'wb') as f:
                for flow in self:
                    try:
                        if store_mode % 2 == 0:
                            if write_header:
                                headers = flow.keys()
                                ip_packet_idx = headers.index('udps.ip_packets')
                                headers.remove('udps.ip_packets')
                                header = ','.join([str(i) for i in headers]) + "\n"
                                f.write(header.encode('utf-8'))
                                write_header = False

                            values = flow.values()
                            del values[ip_packet_idx]
                            csv_converter(values)
                            to_export = ','.join([str(i) for i in values]) + "\n"
                            f.write(to_export.encode('utf-8'))

                        if store_mode > 0:
                            dump_ip_packets(flow, output_sessions_folder)

                    except KeyboardInterrupt:
                        pass

def convert_pcaps(source_files, n_packets, dest_path):
    for file in tqdm.tqdm(source_files):
        for n in n_packets:
            try:
                f = CustomStreamer(source=file, udps=[PacketStore(n=n)])
                f.dump(dest_path, n_packets=n)
            except:
                print(f"{file} couldn't be written")

n_packets = [8]
BENIGN_DEST_PATH = '/mnt/data/InterimData/Benign/'
INTRUSION_DEST_PATH = '/mnt/data/InterimData/Intrusion/'
MALWARE_DEST_PATH = '/mnt/data/InterimData/Malware'

with ProcessPoolExecutor() as executor:
    executor.submit(convert_pcaps, benign_files, n_packets, BENIGN_DEST_PATH)
    executor.submit(convert_pcaps, intrusion_files, n_packets, INTRUSION_DEST_PATH)
    executor.submit(convert_pcaps, malware_files, n_packets, MALWARE_DEST_PATH)

