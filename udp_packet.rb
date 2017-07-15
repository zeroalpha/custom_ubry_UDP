class UDPPacket
  attr_reader :bytes

  def self.create(src,dest,data)
    #@opts = {src: src,dest: dest, data:data, length: data.size + 8}
    x = [src].pack("n")
    x << [dest].pack("n")
    x << [data.size + 8].pack("n")
    x << [0].pack("n")
    x << data
    x
  end

  def initialize(bytes)
    @bytes = bytes
  end

  def src_port
    @bytes[0,2].unpack('n').first
  end

  def dest_port
    @bytes[2,2].unpack('n').first
  end

  def length
    @bytes[4,2].unpack('n').first
  end

  def checksum
    @bytes[6,2].unpack('n').first
  end

  def data
    @bytes[8..-1]
  end

end