require 'rubygems'
require 'ffi/pcap'
require 'r_tcp_ip'

module RTcpIp
  class Packet
    include FFI::Packets::Constants

    attr_reader :l4_hdr

    def l4_hdr
      @l4_hdr
    end
  end
end

pcap = FFI::PCap::Offline.new("./foo.cap")

pcap.loop() do |this,pkt|
  packet = RTcpIp::Packet.new(pkt.body_ptr)

  if packet.tcp?
    puts "#{pkt.time.to_f}:"
    puts "size: #{pkt.len}"
    puts "src: #{packet.src}"
    puts "sport: #{packet.sport}"
    puts "dst: #{packet.dst}"
    puts "dport:#{packet.dport}"
    puts "seq: #{packet.l4_hdr.seq}"
    puts "ack: #{packet.l4_hdr.ack}"
  end

end
