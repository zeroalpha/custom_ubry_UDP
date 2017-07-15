require_relative "./ip_packet.rb"

class EthernetFrame
  attr_reader :bytes

  def self.create(src,dst,data)
    x = dst
    x << src
    x << "\x08\x00" #Type IP
    x << data
  end

  def initialize(bytes)
    @bytes = bytes
  end

  def dest_mac
    @bytes[0,6]
  end

  def src_mac
    @bytes[6,6]
  end

  def data
    IPPacket.new @bytes[14..-1] #14 Bytes header, dann data, dann 4 Bytes checksumme (keine checksumme ?)
  end

  def format_mac(mac)
    mac.bytes.map{|b| sprintf("%02X",b)}.join(':')
  end
end


# \x0a\x00\x27\x00\x00\x00