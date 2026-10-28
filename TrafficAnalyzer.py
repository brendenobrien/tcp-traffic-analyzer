import struct, sys

import packet_struct

class Connection:

    def __init__(self, key):
        self.key = key
        self.packets = []

        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.state = "S0F0"
        self.is_complete = False
        self.start_time = 0.0
        self.end_time = 0.0
        self.duration = 0.0


    def add_packet(self, packet):
        self.packets.append(packet)

    def analyze_state(self):
        for packet in self.packets:
            flags = packet.TCP_header.flags
            if flags.get("SYN") == 1:
                self.syn_count += 1
                if self.syn_count == 1:
                    self.start_time = packet.timestamp
            if flags.get("FIN") == 1:
                self.fin_count += 1
                self.end_time = packet.timestamp
            if flags.get("RST") == 1:
                self.rst_count += 1
        self.state = f"S{self.syn_count}F{self.fin_count}"

        if self.syn_count >= 1 and self.fin_count >= 1:
            self.is_complete = True
            self.duration = round(self.end_time - self.start_time, 6)
    def calculate_metric(self):
        if not self.is_complete:
            return

        client_ip = self.packets[0].IP_header.src_ip

        self.src_to_dst_packets = 0
        self.dst_to_src_packets = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_bytes = 0
        self.window_sizes = []
        self.rtts = []

        pending_acks = {}

        for p in self.packets:
            ip_total_len = p.IP_header.total_len
            ip_header_len = p.IP_header.header_len
            tcp_header_len = p.TCP_header.data_offset

            payload_size = ip_total_len - ip_header_len - tcp_header_len

            if p.IP_header.src_ip == client_ip:
                self.src_to_dst_packets += 1
                self.src_to_dst_bytes += payload_size
            else:
                self.dst_to_src_packets += 1
                self.dst_to_src_bytes += payload_size

            self.window_sizes.append(p.TCP_header.window_size)
            seq_num = p.TCP_header.seq_num
            ack_num = p.TCP_hedaer.ack_num
            flags = p.TCP_header.flags

            if flags.get("ACK") == 1 and ack_num in pending_acks:
                rtt = p.timestamp - pending_acks[ack_num]
                self.rtts.append(round(rtt, 6))
                del pending_acks[ack_num]

            if payload_size > 0:
                expected_ack = seq_num + payload_size
                if expected_ack not in pending_acks:
                    pending_acks[expected_ack] = p.timestamp

            elif flags.get("SYN") == 1 or flags.get("FIN") == 1:
                expected_ack = seq_num + 1
                if expected_ack not in pending_acks:
                    pending_acks[expected_ack] = p.timestamp
# Extract Endian Format
def parse_global_header(filename):
    try:
        f = open(filename, "rb")

    except FileNotFoundError:
        print(f"File with name {filename} could not be found.")
        sys.exit(1)

    global_header = f.read(24)

    if len(global_header) < 24:
        print("File too small to contain global header")
        sys.exit(1)

    magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack("<IHHIIII", global_header)
    if magic == 0xd4c3b2a1:
        print("Swapped endian formatting")
        magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(">IHHIIII", global_header)
        endian = ">"
    elif magic == 0xa1b2c3d4:
        print("Native endian formatting")
        endian = "<"
    else:
        print(f"Unknown magic number {hex(magic)}")
        sys.exit(1)
    return endian, f

def parse_packets(endian, f):
    packet_count = 0
    orig_time = None
    parsed_tcp_packets = []
    head_format = endian + "IIII"

    while(True):
        packet_header = f.read(16)
        packet_count += 1
        if len(packet_header) < 16:
            break
        
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(head_format, packet_header)
        time_absolute = ts_sec + (ts_usec * 0.000001)

        if orig_time == None:
            orig_time = time_absolute

        ts_sec_bytes = packet_header[0:4]
        ts_usec_bytes = packet_header[4:8]

        packet_data = f.read(incl_len)

        tcp_packet = check_tcp_and_process(
            packet_data,
            packet_count,
            ts_sec_bytes,
            ts_usec_bytes,
            orig_time
        )

        if tcp_packet is not None:
            parsed_tcp_packets.append(tcp_packet)
    return parsed_tcp_packets

def check_tcp_and_process(data, count, ts_sec, ts_usec, orig_time):
    if len(data) < 34:
        return None

    protocol_offset = 14+9

    protocol_val = struct.unpack('B', data[protocol_offset: protocol_offset + 1])[0]

    if protocol_val != 6:
        return None

    current_packet = packet_struct.packet()
    current_packet.packet_No_set(count)
    current_packet.timestamp_set(ts_sec, ts_usec, orig_time)

    ip_header_start = 14

    current_packet.IP_header.get_header_len(data[ip_header_start: ip_header_start + 1])

    ip_header_len = current_packet.IP_header.ip_header_len

    current_packet.IP_header.get_total_len(data[ip_header_start + 2: ip_header_start + 4])

    src_ip_offset = ip_header_start + 12
    buffer1 = data[src_ip_offset: src_ip_offset + 4]

    dest_ip_offset = ip_header_start + 16
    buffer2 = data[dest_ip_offset: dest_ip_offset + 4]

    current_packet.IP_header.get_IP(buffer1, buffer2)

    tcp_header_start = ip_header_start + ip_header_len
    if len(data) < tcp_header_start + 20:
        return None
    # Extract TCP Source Port
    current_packet.TCP_header.get_src_port(data[tcp_header_start: tcp_header_start + 2])
    # Extract Destination Port
    current_packet.TCP_header.get_dst_port(data[tcp_header_start + 2: tcp_header_start + 4])
    # Extract SEQ Num
    current_packet.TCP_header.get_seq_num(data[tcp_header_start + 4: tcp_header_start + 8])
    # Extract ACK Num
    current_packet.TCP_header.get_ack_num(data[tcp_header_start + 8: tcp_header_start + 12])
    # Extract Data Offset
    current_packet.TCP_header.get_data_offset(data[tcp_header_start + 12: tcp_header_start + 13])
    # Extract Flags
    current_packet.TCP_header.get_flags(data[tcp_header_start + 13: tcp_header_start + 14])
    # Extract Window Size
    windowb1 = data[tcp_header_start + 14: tcp_header_start + 15]
    windowb2 = data[tcp_header_start + 15: tcp_header_start + 16]
    current_packet.TCP_header.get_window_size(windowb1, windowb2)
    print(current_packet.TCP_header.flags)

    return current_packet
def group_into_connections(packet_list) -> dict:
    connection_dict = {}
    for packet in packet_list:
        src_ip = packet.IP_Header.src_ip
        dst_ip = packet.IP_Header.dst_ip
        src_port = packet.IP_Header.src_port
        dst_port = packet.IP_Header.dst_port

        if src_ip < dst_ip:
            key = (src_ip, src_port, dst_ip, dst_port)
        else:
            key = (dst_ip, dst_port, src_ip, src_port)

        if key not in connection_dict:
            connection_dict[key] = Connection(key)

        connection_dict[key].add_packet(packet)
    return connection_dict
if __name__ == "__main__":
    filename = "sample-capture-file.cap"

    endian, f = parse_global_header(filename)
    packets = parse_packets(endian, f)

    connections = group_into_connections(packets)
    #packets = parse_packets()

    

