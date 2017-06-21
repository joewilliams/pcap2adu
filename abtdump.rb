require 'rubygems'
require 'packetfu'
require 'docopt'
require 'sqlite3'
require 'securerandom'
require 'ipaddr'
require 'ffi/pcap'
require 'ffi/packets'

DOC = <<DOCOPT
Usage:
  #{__FILE__} go
Options:
  #{__FILE__} go --file=<pcap_file>
  #{__FILE__} go --interface=<iface> --filter=<filter>
DOCOPT

module RTcpIp
  class Packet
    include FFI::Packets::Constants

    attr_reader :l4_hdr

    def l4_hdr
      @l4_hdr
    end
  end
end

def ip2int(ip)
  IPAddr.new(ip).to_i
end

def int2ip(int)
  IPAddr.new(int, family = Socket::AF_INET).to_s
end

def int2flags(int)
  b = PacketFu::TcpFlags.new
  b.read(int.to_s(16).hex.chr)
end

def create_db()
  db = SQLite3::Database.new ":memory:"

  db.execute "CREATE TABLE IF NOT EXISTS Packets(
    Id Text PRIMARY KEY,
    Timestamp REAL,
    Size INT,
    Src INT,
    Sport INT,
    Dst INT,
    Dport INT,
    Seq INT,
    Ack INT,
    Flags INT
  )"

  db
end

def create_packet_record(db, pcap_obj)
  id = SecureRandom.uuid

  packet = PacketFu::TCPPacket.new
  packet.read(pcap_obj.body)

  if packet.is_tcp?
    db.execute "INSERT INTO Packets VALUES(
      '#{id}',
      #{pcap_obj.time.to_f},
      #{packet.payload.size},
      #{packet.ip_src},
      #{packet.tcp_src},
      #{packet.ip_dst},
      #{packet.tcp_dst},
      #{packet.tcp_seq},
      #{packet.tcp_ack},
      #{packet.tcp_flags.to_i}
    )"
  end
end

def follow_flow(db, dport = false, client_ip = false)
  syn_packets_stm = db.prepare "SELECT * FROM Packets where Flags=2"
  syn_packets = syn_packets_stm.execute

  syn_packets.each do |row|
    packets = []
    packets_to = get_packets(db, row['Src'], row['Sport'], row['Dst'], row['Dport'])
    packets_from = get_packets(db, row['Dst'], row['Dport'], row['Src'], row['Sport'])

    packets << packets_to
    packets << packets_from

    packets.flatten.sort_by { |packet| packet['Timestamp'] }

    puts '===='
    puts "flow:"
    packets.each_with_index do |pkt, i|
      puts pkt
    end
    puts '===='

  end
end

def get_packets(db, src, sport, dst, dport, seq = false)
  packets_stm = db.prepare "SELECT * FROM Packets where Src=#{src} and Sport=#{sport} and Dst=#{dst} and Dport=#{dport}"
  packets = packets_stm.execute
  packets.to_a
end

def process_pcap(db, pcap)
  pcap.loop() do |this,pkt|
    create_packet_record(db, pkt)
  end
end

def main
  begin
    if Docopt::docopt(DOC)['--file']
      pcap_file = Docopt::docopt(DOC)['--file']
      pcap = FFI::PCap::Offline.new(pcap_file)
    end

    db = create_db()
    db.results_as_hash = true
    process_pcap(db, pcap)
    follow_flow(db)

  rescue Docopt::Exit => e
    puts e.message
  end
end

main
