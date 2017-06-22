module RTcpIp
  class Packet
    include FFI::Packets::Constants

    attr_reader :l4_hdr

    def l4_hdr
      @l4_hdr
    end
  end
end
