import socket

from struct import pack


class Packet():
    def __init__(self, src_ip, dest_ip, src_port, dest_port):
        ## IP segment
        self.version   = 0x04
        self.ihl       = 0x05
        self.tos       = 0x00
        self.identity  = 0xabcd
        self.flags     = 0x00
        self.frag_off  = 0x00
        self.ttl       = 0x00
        self.protocol  = 0x06
        self.checksum  = 0x00
        self.src_ip    = src_ip
        self.dest_ip   = dest_ip
        self.src_addr  = socket.inet_aton(self.src_ip)
        self.dest_addr = socket.inet_aton(self.dest_ip)
        self.v_ihl     = (self.version << 4) + self.ihl
        self.f_fo      = (self.flags   << 1) + self.frag_off

        ## TCP segment 
        self.src_port    = src_port
        self.dest_port   = dest_port
        self.seq_no      = 0x00
        self.ack_no      = 0x00
        self.data_off    = 0x05
        self.reserved    = 0x00
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0
        self.window_size = 0x7110
        self.checksum    = 0x00
        self.urg_pointer = 0x00
        self.data_offset_res_flags = (self.data_off << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin

        ####
        # Packet
        self.ip_header  = b""
        self.tcp_header = b""
        self.packet     = self.ip_header + self.tcp_header
    

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1] 
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header
                                      

    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags, self.window_size,
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header

    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum(self.generate_tmp_ip_header),
                                          self.src_addr,
                                          self.dest_addr)

        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header

        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)

        self.ip_header  = final_ip_header
        self.tcp_header = final_tcp_header

        self.packet = final_ip_header + final_tcp_header


                        