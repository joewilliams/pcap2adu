module Pcap2adu
  class Utils
    def self.ip2int(ip)
      IPAddr.new(ip).to_i
    end

    def self.int2ip(int)
      IPAddr.new(int, family = Socket::AF_INET).to_s
    end

    def self.int2flags(int)
      b = PacketFu::TcpFlags.new
      b.read(int.to_s(16).hex.chr)
    end
  end
end
