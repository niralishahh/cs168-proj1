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

        v_str = b[0:4] 
        self.version = int(v_str, 2)

        self.header_len = int(b[4:8], 2) * 4

        tos_str = b[8:16]
        self.tos = int(tos_str, 2)

        total_len_str = b[16:32]
        self.length = int(total_len_str, 2)
        
        id_str = b[32:48]
        self.id = int(id_str, 2)

        flags_str = b[48:51] 
        self.flags = int(flags_str, 2)

        frag_o_str = b[51:64]
        self.frag_offset = int(frag_o_str, 2) 

        ttl_str = b[64:72]
        self.ttl = int(ttl_str, 2)

        proto_str = b[72:80]
        self.proto = int(proto_str, 2)

        cksum_str = b[80:96]
        self.cksum = int(cksum_str, 2)

        src_1, src_2, src_3, src_4 = int(b[96:104],2), int(b[104:112],2), int(b[112:120],2), int(b[120:128],2)
        self.src = str(src_1) + "." + str(src_2) +  "." + str(src_3) +  "." + str(src_4) 

        dst1, dst2, dst3, dst4 = int(b[128: 136], 2), int(b[136: 144], 2), int(b[144:152], 2), int(b[152:160], 2)
        self.dst = str(dst1) + "." + str(dst2) +  "." + str(dst3) +  "." + str(dst4)


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
        b = ''.join(format(byte, '08b') for byte in [*buffer])

        type_str = b[0:8]
        self.type = int(type_str, 2)

        code_str = b[8:16]
        self.code = int(code_str, 2)

        cksum_str = b[16: 32]
        self.cksum = int(cksum_str, 2)
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

        src_port_str = b[0:16]
        self.src_port = int(src_port_str, 2)

        dst_port_str = b[16:32]
        self.dst_port = int(dst_port_str, 2)

        len_str = b[32:48] 
        self.len = int(len_str, 2)

        cksum_str = b[48:64]
        self.cksum = int(cksum_str, 2)
        pass  # TODO

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like
def probe(sendsock: util.Socket, recvsock: util.Socket, ttl: int, dest_ip: str, seen: set): 
    res = []
    for i in range(PROBE_ATTEMPT_COUNT):
        sendsock.set_ttl(ttl)
        sendsock.sendto("Potato".encode(), (dest_ip, 33436))
        if recvsock.recv_select():  # Check if there's a packet to process.
            buf, address = recvsock.recvfrom()  # Receive the packet.
            if address[0] == dest_ip:
                return [address[0]]
            if address[0] not in seen: 
                seen.add(address[0])
                res.append(address[0])

    return res


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


    # print(ip)
    # sendsock.set_ttl(3)
    # sendsock.sendto("Potato".encode(), (ip, 33436))

    # if recvsock.recv_select():  # Check if there's a packet to process.
    #     buf, address = recvsock.recvfrom()  # Receive the packet.
    #     # Print out the packet for debugging.
    #     print(f"Packet bytes: {buf.hex()}")
    #     # print(f"Packet is from IP: {address[0]}")
    #     # print(f"Packet is from port: {address[1]}")
    #     print(ICMP(buffer=buf))
    #     print(UDP(buffer=buf))
    #     print(IPv4(buffer=buf))

    res = []
    seen = set()
    ttl_count = 1
    while (not res) or res[-1] != [ip]: 
        ans = probe(sendsock=sendsock, recvsock=recvsock, ttl=ttl_count, dest_ip=ip,seen=seen)
        if ans: 
            res.append(ans)
        ttl_count+=1

    
    print(res)
    return res


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
