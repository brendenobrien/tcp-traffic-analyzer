import struct, sys

import packet_struct

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

def parse_packets(f, endian):
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

    return current_packet
if __name__ == "__main__":
    filename = "sample-capture-file.cap"

    endian, f = parse_global_header(filename)
    print(parse_packets(f, endian))
    

