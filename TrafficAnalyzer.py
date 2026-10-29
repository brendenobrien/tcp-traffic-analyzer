import os
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
        self.state = f"S{self.syn_count}F{self.fin_count}" if self.rst_count == 0 else f"S{self.syn_count}F{self.fin_count}/R"

        if self.syn_count >= 1 and self.fin_count >= 1:
            self.is_complete = True
            self.duration = round(self.end_time - self.start_time, 6)

    def calculate_metric(self):
        if not self.is_complete:
            return

        client = (self.packets[0].IP_header.src_ip, self.packets[0].TCP_header.src_port)
    

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

            if p.IP_header.src_ip == client[0]:
                self.src_to_dst_packets += 1
                self.src_to_dst_bytes += payload_size
            else:
                self.dst_to_src_packets += 1
                self.dst_to_src_bytes += payload_size

            from_client = (p.IP_header.src_ip, p.TCP_header.src_port) == client
            self.window_sizes.append(p.TCP_header.window_size)
            flags = p.TCP_header.flags
            if from_client:
                if payload_size > 0:
                    expected_ack = p.TCP_header.seq_num + payload_size
                elif flags.get("SYN") == 1 or flags.get("FIN") == 1:
                    expected_ack = p.TCP_header.seq_num + 1
                else:
                    expected_ack = None
                if expected_ack is not None and expected_ack not in pending_acks:
                    pending_acks[expected_ack] = p.timestamp
            elif flags.get("ACK") == 1 and p.TCP_header.ack_num in pending_acks:
                self.rtts.append(p.timestamp - pending_acks.pop(p.TCP_header.ack_num))
                
    def is_open(self):
        last_fin = None
        for i, packet in enumerate(self.packets):
            if packet.TCP_header.flags.get("FIN") == 1:
                last_fin = i
        if last_fin is None:
            return True
        for packet in self.packets[last_fin + 1:]:
            payload_size = packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset
            if payload_size > 0:
                return True
        return False

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
            time_absolute,
            orig_time
        )

        if tcp_packet is not None:
            packets.append(tcp_packet)
    f.close()
    return packets

def check_tcp_and_process(data, count, time_absolute, orig_time):
    if len(data) < 34:
        return None
    
    protocol_val = struct.unpack('B', data[23:24])[0]

    if protocol_val != 6:
        return None
    
    # Create packet object
    packet = packet_struct.packet()
    packet.packet_No_set(count)
    packet.timestamp = round(time_absolute - orig_time, 6)

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
        connection_dict[key].add_packet(packet)
    return connection_dict

def analyze_connections(connections: dict):

    complete_connections = []

    # Analyze state of every connection and create list of completed ones.
    for conn in connections.values():
        conn.analyze_state()

        if conn.is_complete:
            complete_connections.append(conn)

    return complete_connections

def print_report(connections: dict, complete_connections: list):
    print(f"A) Total number of connections: {len(connections)}")
    print()
    print("-" * 40)
    print()
    print("B) Connections' Details")
    print()
    reset_connections = 0
    before_capture = 0
    open_connections = 0
    count = 0
    for conn in connections.values():
        if count != 0:
            print("+" * 40)
        conn: Connection
        if conn.is_open():
            open_connections += 1
        if conn.rst_count >= 1:
            reset_connections += 1
        if conn.packets[0].TCP_header.flags.get("SYN") != 1:
            before_capture += 1
        count += 1
        
        print(f"Connection {count}:")
        print(f"Source Address: {conn.packets[0].IP_header.src_ip}")
        print(f"Destination Address: {conn.packets[0].IP_header.dst_ip}")
        print(f"Source Port: {conn.packets[0].TCP_header.src_port}")
        print(f"Destination Port: {conn.packets[0].TCP_header.dst_port}")
        print(f"Status: {conn.state}")
        if conn.is_complete:
            print(f"Start Time: {conn.start_time:.6f}s")
            print(f"End Time: {conn.end_time:.6f}s")
            print(f"Duration: {(conn.end_time - conn.start_time):.6f}s")
            print(f"Number of packets sent from Source to Destination: {conn.src_to_dst_packets}")
            print(f"Number of packets sent from Destination to Source: {conn.dst_to_src_packets}")
            print(f"Total Number of packets: {conn.src_to_dst_packets + conn.dst_to_src_packets}")
            print(f"Number of data bytes sent from Source to Destination: {conn.src_to_dst_bytes}B")
            print(f"Number of data bytes sent from Destination to Source: {conn.dst_to_src_bytes}B")
            print(f"Total Number of Data Bytes: {conn.dst_to_src_bytes + conn.src_to_dst_bytes}B")
        print("END")
    print()
    print("-" * 40)
    print()
    print("C) General")
    print()
    print(f"Total Number of Complete TCP Connections: {len(complete_connections)}")
    print(f"Total Number of Reset TCP Connections: {reset_connections}")
    print(f"Number of TCP Connections still open when the trace capture ended: {open_connections}")
    print(f"Number of TCP Connections established before the capture started: {before_capture}")
    print("-" * 40)
    complete_connection_statistics(complete_connections)

def complete_connection_statistics(complete_connections: list):
    durations = [c.end_time - c.start_time for c in complete_connections]
    rtts = [r for c in complete_connections for r in c.rtts]
    packets = [len(c.packets) for c in complete_connections]
    windows = [w for c in complete_connections for w in c.window_sizes]
    if not complete_connections:
        print("There were no complete TCP connections...")
        return
    print()
    print("D) Complete TCP Connections:")
    print()
    print(f"Minimum Time Duration: {min(durations):.6f}s")
    print(f"Mean Time Duration: {sum(durations) / len(durations):.6f}s")
    print(f"Maximum Time Duration: {max(durations):.6f}s")
    print()
    if rtts:
        print(f"Minimum RTT Value: {min(rtts):.6f}s")
        print(f"Mean RTT Value: {sum(rtts) / len(rtts):.6f}s")
        print(f"Maximum RTT Value: {max(rtts):.6f}s")
    else:
        print("Minimum RTT Value: N/A")
        print("Mean RTT Value: N/A")
        print("Maximum RTT Value: N/A")
    print()
    print(f"Minimum Number of Packets including both send/received: {min(packets)}")
    print(f"Mean Number of Packets including both send/received: {sum(packets) / len(packets):.6f}")
    print(f"Maximum Number of Packets including both send/received: {max(packets)}")
    print()
    print(f"Minimum Receive Window Size including both send/received: {min(windows)}B")
    print(f"Mean Receive Window Size including both send/received: {sum(windows) / len(windows):.6f}B")
    print(f"Maximum Receive Window Size including both send/received: {max(windows)}B")

if __name__ == "__main__":

    if len(sys.argv) > 1:
        filename = sys.argv[1] # If file provided in command line, use this one
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(script_dir, "sample-capture-file.cap") # default file
 
    endian, f = parse_global_header(filename)
    packets = parse_packets(endian, f)
    connections = group_into_connections(packets)
    complete_connections = analyze_connections(connections)
    for c in complete_connections:
        c.calculate_metric()
    
    print_report(connections, complete_connections)
    

