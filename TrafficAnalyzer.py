import struct, sys, io

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
            ip_header_len = p.IP_header.ip_header_len
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
            ack_num = p.TCP_header.ack_num
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
def parse_global_header(filename: str):
    try:
        # Open cap file
        f = open(filename, "rb")
    # End program if file does not exist
    except FileNotFoundError:
        print(f"File with name {filename} could not be found.")
        sys.exit(1)
    # Read global header
    global_header = f.read(24)
    # Header too small to be a global header, something is wrong, exit.
    if len(global_header) < 24:
        print("File too small to contain global header")
        sys.exit(1)

    # Grab magic number
    magic = struct.unpack("<I", global_header[:4])[0]
    if magic == 0xd4c3b2a1:
        #print("Swapped endian formatting")
        endian = ">"
    elif magic == 0xa1b2c3d4:
        #print("Native endian formatting")
        endian = "<"
    else:
        print(f"Unknown magic number {hex(magic)}")
        sys.exit(1)
    return endian, f

def parse_packets(endian: str, f: io.BufferedReader) -> list:
    packet_count = 0
    orig_time = None
    packets = []
    head_format = endian + "IIII"

    while(True):
        # Read packet header
        packet_header = f.read(16)
        packet_count += 1

        # Exit if data read is less than header size, i.e., end of file has been reached
        if len(packet_header) < 16:
            break

        # Extract header data
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(head_format, packet_header)
        time_absolute = ts_sec + (ts_usec * 0.000001)

        if orig_time == None:
            orig_time = time_absolute
        # Read packet data
        packet_data = f.read(incl_len)

        # Process packet data
        tcp_packet = check_tcp_and_process(
            packet_data,
            packet_count,
            packet_header[0:4],
            packet_header[4:8],
            orig_time
        )

        if tcp_packet is not None:
            packets.append(tcp_packet)
    f.close()
    return packets

def check_tcp_and_process(data, count, ts_sec, ts_usec, orig_time):
    if len(data) < 34:
        return None
    
    protocol_val = struct.unpack('B', data[23:24])[0]

    if protocol_val != 6:
        return None
    
    # Create packet object
    packet = packet_struct.packet()
    packet.packet_No_set(count)
    packet.timestamp_set(ts_sec, ts_usec, orig_time)

    ip = 14

    packet.IP_header.get_header_len(data[ip: ip + 1]) 
    packet.IP_header.get_total_len(data[ip + 2:ip + 4])

    # Extract IP addresses for destination and source
    packet.IP_header.get_IP(data[26:30], data[30:34])

    tcp = ip + packet.IP_header.ip_header_len
    if len(data) < tcp + 20:
        return None
    # Extract TCP Source Port
    packet.TCP_header.get_src_port(data[tcp: tcp + 2])

    # Extract Destination Port
    packet.TCP_header.get_dst_port(data[tcp + 2: tcp + 4])

    # Extract SEQ Num
    packet.TCP_header.get_seq_num(data[tcp + 4: tcp + 8])

    # Extract ACK Num
    packet.TCP_header.get_ack_num(data[tcp + 8: tcp + 12])

    # Extract Data Offset
    packet.TCP_header.get_data_offset(data[tcp + 12: tcp + 13])

    # Extract Flags
    packet.TCP_header.get_flags(data[tcp + 13: tcp + 14])

    # Extract Window Size
    packet.TCP_header.get_window_size(data[tcp + 14: tcp + 15], data[tcp + 15: tcp + 16])
    return packet

def group_into_connections(packet_list: list) -> dict:
    connection_dict = {}
    for packet in packet_list:
        if packet.IP_header.src_ip < packet.IP_header.dst_ip:
            key = (
                packet.IP_header.src_ip,
                packet.TCP_header.src_port,
                packet.IP_header.dst_ip,
                packet.TCP_header.dst_port
                )
        else:
            key = (
                packet.IP_header.dst_ip,
                packet.TCP_header.dst_port, 
                packet.IP_header.src_ip, 
                packet.TCP_header.src_port
                )

        if key not in connection_dict:
            connection_dict[key] = Connection(key)
         #   print(key)
        connection_dict[key].add_packet(packet)
    return connection_dict

def analyze_connections(connections: dict):
    complete_connections = []

    for key, conn in connections.items():
        conn.analyze_state()

        if conn.is_complete:
            complete_connections.append(conn)

    return complete_connections

def print_report(connections: dict, complete_connections: list):
    print(f"Total Number of Connections: {len(connections)}")
    print()
    reset_connections = 0
    before_capture = 0
    #print(connections)
    count = 0
    for conn in connections.values():
        conn: Connection
        if conn.rst_count >= 1:
            reset_connections += 1
        if conn.syn_count == 0:
            before_capture += 1
        count += 1
        print(f"Connection {count}:")
        print(f"Source Address: {conn.packets[0].IP_header.src_ip}")
        print(f"Destination Address: {conn.packets[0].IP_header.dst_ip}")
        print(f"Source Port: {conn.packets[0].TCP_header.src_port}")
        print(f"Destination Port: {conn.packets[0].TCP_header.dst_port}")
        print(f"Status: {conn.state}")
        if conn in complete_connections:
            print(conn.rtts)
            print(f"Start Time: {conn.start_time}")
            print(f"End Time: {conn.end_time}")
            print(f"Duration: {round(conn.end_time - conn.start_time, 6)}")
            print(f"Number of packets sent from Source to Destination: {conn.src_to_dst_packets}")
            print(f"Number of packets sent from Destination to Source: {conn.dst_to_src_packets}")
            print(f"Total Number of packets: {conn.src_to_dst_packets + conn.dst_to_src_packets}")
            print(f"Number of data bytes sent from Source to Destination: {conn.src_to_dst_bytes}B")
            print(f"Number of data bytes sent from Destination to Source: {conn.dst_to_src_bytes}B")
            print(f"Total Number of Data Bytes: {conn.dst_to_src_bytes + conn.src_to_dst_bytes}B")
        print("END")
        print("+" * 40)
        print("General")
        print()
        print(f"Total Number of Complete TCP Connections: {len(complete_connections)}")
        print(f"Total Number of Reset TCP Connections: {reset_connections}")
        print(f"Number of TCP Connections still open when the trace capture ended: {len(connections) - len(complete_connections)}")
        print(f"Number of TCP Connections established before the capture started: {before_capture}")
        print("-" * 0)
        complete_connection_statistics(complete_connections)

def complete_connection_statistics(complete_connections: list):
    durations = [c.end_time - c.start_time for c in complete_connections]
    rtts = [r for c in complete_connections for r in c.rtts]
    packets = [len(c.packets) for c in complete_connections]
    windows = [w for c in complete_connections for w in c.window_sizes]

    print("Complete TCP Connections:")
    print()
    print(f"Minimum Time Duration: {min(durations):.6f}")
    print(f"Mean Time Duration: {sum(durations) / len(durations):.6f}")
    print(f"Maximum Time Duration: {max(durations):6f}")
    print()
    print(f"Minimum RTT Value: {min(rtts):.6f}")
    print(f"Mean RTT Value: {sum(rtts) / len(rtts):.6f}")
    print(f"Maximum RTT Value: {max(rtts):.6f}")
    print()
    print(f"Minimum Number of Packets including both send/received: {min(packets)}")
    print(f"Mean Number of Packets including both send/received: {sum(packets) / len(packets):.6f}")
    print(f"Maximum Number of Packets including both send/received: {max(packets)}")
    print()
    print(f"Minimum Receive Window Size including both send/received: {min(windows):.6f}")
    print(f"Mean Receive Window Size including both send/received: {sum(windows) / len(windows):.6f}")
    print(f"Maximum Receive Window Size including both send/received: {max(windows):.6f}")
if __name__ == "__main__":
    filename = "sample-capture-file.cap"
    endian, f = parse_global_header(filename)
    packets = parse_packets(endian, f)
    connections = group_into_connections(packets)
    complete_connections = analyze_connections(connections)
    for c in complete_connections:
        c.calculate_metric()
    
    print_report(connections, complete_connections)
    

