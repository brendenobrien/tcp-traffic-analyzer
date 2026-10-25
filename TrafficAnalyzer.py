import struct, sys

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

        

        print(f"ts_sec: {ts_sec}")
        print(f"ts_usec: {ts_usec}")
        print(f"time_absolute: {time_absolute}")
        print(f"incl_len: {incl_len}")
        print(f"orig_len: {orig_len}")

        print(f"packet_data: {packet_data}")

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
    pass;
if __name__ == "__main__":
    filename = "sample-capture-file.cap"

    endian, f = parse_global_header(filename)
    parse_packets(f, endian)

