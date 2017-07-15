require 'socket'
require 'hexdump'

require_relative './ethernet_frame.rb'

require 'pry'

#unless ARGV[0] =~ /^(eth\d+|lo)$/
unless ARGV[0]
  puts "eth0 or lo required as argument"
  exit 1
end

if_name = ARGV[0]
#if_name = 'eth0'
#if_name = 'lo'


# Size in bytes of a C `ifreq` structure on a 64-bit system
# http://man7.org/linux/man-pages/man7/netdevice.7.html 
#
# struct ifreq {
#     char ifr_name[IFNAMSIZ]; /* Interface name */
#     union {
#         struct sockaddr ifr_addr;
#         struct sockaddr ifr_dstaddr;
#         struct sockaddr ifr_broadaddr;
#         struct sockaddr ifr_netmask;
#         struct sockaddr ifr_hwaddr;
#         short           ifr_flags;
#         int             ifr_ifindex;
#         int             ifr_metric;
#         int             ifr_mtu;
#         struct ifmap    ifr_map;
#         char            ifr_slave[IFNAMSIZ];
#         char            ifr_newname[IFNAMSIZ];
#         char           *ifr_data;
#     };
# };
#
IFREQ_SIZE = 0x0028

# Size in bytes of the `ifr_ifindex` field in the `ifreq` structure
IFINDEX_SIZE = 0x0004

# Operation number to fetch the "index" of the interface
SIOCGIFINDEX = 0x8933

sock = Socket.open(:PACKET, :RAW)

# Convert the interface name into a string of bytes
# padded with NULL bytes to make it `IFREQ_SIZE` bytes long
# a -> binary string padded with count NULL Bytes
ifreq = [if_name].pack('a' + IFREQ_SIZE.to_s)
puts "Finding Device index of #{if_name}"
sock.ioctl(SIOCGIFINDEX, ifreq)
#binding.pry

if_index = ifreq[Socket::IFNAMSIZ, IFINDEX_SIZE]
puts "#{if_name} has index #{if_index.bytes}"

# Receive every packet
ETH_P_ALL = 0x0300

# Size in bytes of a C `sockaddr_ll` structure on a 64-bit system
#
# struct sockaddr_ll {
#     unsigned short sll_family;   /* Always AF_PACKET */
#     unsigned short sll_protocol; /* Physical-layer protocol */
#     int            sll_ifindex;  /* Interface number */
#     unsigned short sll_hatype;   /* ARP hardware type */
#     unsigned char  sll_pkttype;  /* Packet type */
#     unsigned char  sll_halen;    /* Length of address */
#     unsigned char  sll_addr[8];  /* Physical-layer address */
# };
#
SOCKADDR_LL_SIZE = 0x0014

# s | Integer | 16-bit signed, native endian (int16_t)
sockaddr_ll = [Socket::AF_PACKET].pack('s')
sockaddr_ll << [ETH_P_ALL].pack('s')
sockaddr_ll << if_index
# mit NULL bytes auf SOCKADDR_LL_SIZE auffüllen
sockaddr_ll << ("\x00" * (SOCKADDR_LL_SIZE - sockaddr_ll.size))
puts "Binding RAW socket to #{if_name}"
sock.bind(sockaddr_ll)
puts "Bound"
#binding.pry

#puts sockaddr_ll.bytes


BUFFER_SIZE = 1024
hello = []
results = []
global_data = []


loop do
  begin
    puts "Receiving ... "
    data = sock.recv(BUFFER_SIZE)
    global_data << data
    puts "Hexdump of Packet::"
    Hexdump.dump(data)
    puts "End of Dump"

    frame = EthernetFrame.new(data)
    next unless frame.data.protocol == IPPacket::UDP_PROTOCOL && frame.data.data.dest_port == 4321

    opt = {
      dest_port: [frame.data.data.src_port].pack('n'),
      dest_ip_addr: frame.data.src_adress.pack('CCCC'),
      dest_mac_addr: frame.src_mac,

      src_port: [frame.data.data.dest_port].pack('n'),
      src_ip_addr: frame.data.dest_adress.pack('CCCC'),
      src_mac_addr: frame.dest_mac
    }

    puts "Received #{data.size} Bytes from #{opt[:src_mac]} with IP: #{frame.data.src_adress(true)}:#{frame.data.data.src_port}"
    
    #UDP
    new_frame = opt[:dest_mac_addr]
    new_frame << opt[:src_mac_addr]
    new_frame << "\x08\x00"
    #IP
    new_frame << frame.data.bytes[0] #IP Version / IHL
    new_frame << frame.data.bytes[1] #DSCP / ECN
    new_frame << frame.data.bytes[2] # total length
    new_frame << frame.data.bytes[3] # total length
    #new_frame += 

    #Hexdump.dump(data)
    #hello << data if data.scan(/hello/i)
    #results << data
  rescue Exception => e
    puts e.inspect
    break
  end
end
binding.pry
puts "===================="
hello.each{|h| Hexdump.dump(h)}