#https://en.wikipedia.org/wiki/IPv4#Packet_structure

require_relative './udp_packet.rb'

class IPPacket
  attr_reader :bytes
  @@protocol_names = {
    0x11 => "UDP"
  }

  UDP_PROTOCOL = 0x11

  
  class UnknownProtocolError < StandardError; end

  def self.create(src,dest,data)
    x = "\x45" #IP Version = 4 and IHL = 5
    x << "\x00" #DSCP/ECN
    x << [20 + data.size].pack("n") #Length
    x << [0].pack("n")  #Identification
    x << [0b0100000000000000].pack("n")# Flags (010) and Fragment Offset
    x << "\x20" # TTL
    x << "\x11" # protocol UDP
    x << [0].pack("n") # Checksum
    x << [src,dest].pack("NN")
    x << data
    x
  end

  def initialize(bytes)
    @bytes = bytes
  end

  def version
    #@bytes[0] besteht auf 4 Bits Version und 4 Bits IHL
    @bytes[0].ord << 4
  end

  def ihl
    @bytes[0].ord & 0b00001111 # oder 0xF
  end

  def src_adress(human_readable = false)
    if human_readable then
      @bytes[12,4].bytes.map(&:to_s).join('.')
    else
      @bytes[12,4].bytes
    end
  end

  def dest_adress(human_readable = false)
    if human_readable then
      @bytes[16,4].bytes.map(&:to_s).join('.')
    else
      @bytes[16,4].bytes
    end
  end

  def protocol(human_readable = false)
    if human_readable then
      @@protocol_names[@bytes[9]]
    else
      @bytes[9].ord
    end  
  end

  def data
    # ICMP Wrap 8 bytes
    # IP Header Copy 20 bytes
    case protocol
    when UDP_PROTOCOL
      UDPPacket.new(@bytes[20..-1])
    else
      raise UnknownProtocolError, "Protocol with ID #{protocol} not found"
    end
  end
end