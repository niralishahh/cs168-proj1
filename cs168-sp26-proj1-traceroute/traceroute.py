import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])

        v_str = b[0:8] 
        version = int(v_str, 2)

        h_len = 20

        tos_str = b[8:16]
        tos = int(tos_str, 2)

        total_len_str = b[16:32]
        total_len = int(total_len_str, 2)
        
        id_str = b[32:48]
        id = int(id_str, 2)

        flags_str = b[48:56] 
        flags = int(flags_str, 2)

        frag_o_str = b[56:64]
        frag_offset = int(frag_o_str, 2)

        ttl_str = b[64:72]
        ttl = int(ttl_str, 2)

        proto_str = b[72:80]
        proto = int(proto_str, 2)

        cksum_str = b[80:96]
        cksum = int(cksum_str, 2)

        src_str = b[96:128]
        src = int(src_str, 2)

        dst_str = b[128:160]
        dst = int(dst_str, 2)


        pass  # TODO

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
    
        pass  # TODO

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])

        src_port_str = b[384:400]
        src_port = int(src_port_str, 2)

        dst_port_str = b[400:416]
        dst_post = int(dst_port_str, 2)

        len_str = b[416:432] 
        len = int(len_str, 2)

        cksum_str = b[432:464]
        cksum = int(cksum_str, 2)
        pass  # TODO

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    # for ttl in range(1, TRACEROUTE_MAX_TTL+1):
    #     util.print_result([], ttl)
    # return []
    print(ip)
    sendsock.set_ttl(30)
    sendsock.sendto("Potato".encode(), (ip, 33436))

    if recvsock.recv_select():  # Check if there's a packet to process.
        buf, address = recvsock.recvfrom()  # Receive the packet.
        # Print out the packet for debugging.
        print(f"Packet bytes: {buf.hex()}")
        # print(f"Packet is from IP: {address[0]}")
        # print(f"Packet is from port: {address[1]}")

    


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
