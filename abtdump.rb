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
    Flags INT,
    Direction Text,
    Session Text
  )"

  db.execute "CREATE TABLE IF NOT EXISTS Sessions(
    Id Text PRIMARY KEY
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
      #{packet.tcp_flags.to_i},
      NULL,
      NULL
    )"
  end
end

def populate_tcp_sessions(db)
  syn_packets_stm = db.prepare "SELECT * FROM Packets where Flags=2"
  syn_packets = syn_packets_stm.execute

  syn_packets.each do |packet|
    populate_tcp_session(db, packet['Src'], packet['Sport'], packet['Dst'], packet['Dport'])
  end
end

def populate_tcp_session(db, src, sport, dst, dport)
  packets_to = get_packets_by_src_dst(db, src, sport, dst, dport)
  packets_from = get_packets_by_src_dst(db, dst, dport, src, sport)

  packets_to.sort_by! { |packet| packet['Timestamp'] }
  packets_from.sort_by! { |packet| packet['Timestamp'] }

  flow_id = SecureRandom.uuid

  db.execute "INSERT INTO Sessions VALUES('#{flow_id}')"

  packets_to.each do |packet|
    db.execute "UPDATE Packets SET Direction='to', Session='#{flow_id}' where Id='#{packet['Id']}'"
  end

  packets_from.each do |packet|
    db.execute "UPDATE Packets SET Direction='from', Session='#{flow_id}' where Id='#{packet['Id']}'"
  end
end

def get_packets_by_src_dst(db, src, sport, dst, dport, seq = false)
  packets_stm = db.prepare "SELECT * FROM Packets where Src=#{src} and Sport=#{sport} and Dst=#{dst} and Dport=#{dport}"
  packets = packets_stm.execute
  packets.to_a
end

def process_pcap(db, pcap)
  pcap.loop() do |this,pkt|
    create_packet_record(db, pkt)
  end
end

def follow_session(packets)
  start_timestamp = nil

  packets.each_with_index do |packet, i|
    case packet['Flags']
    when 2 # syn
      start_timestamp = packet['Timestamp']
      puts "SYN: #{'%.6f' % packet['Timestamp']} #{int2ip(packet['Src'])}:#{packet['Sport']} > #{int2ip(packet['Dst'])}:#{packet['Dport']}"
    when 17 # fin
      case packet['Direction']
      when 'to'
        # we only really care when the client sent the FIN
        rtt = '%.10f' % ( packet['Timestamp'] - packets[i - 1]['Timestamp'] )
        elapsed_time = '%.10f' % ( packet['Timestamp'] - start_timestamp )
        puts "FIN: #{'%.6f' % packet['Timestamp']} #{int2ip(packet['Src'])}:#{packet['Sport']} > #{int2ip(packet['Dst'])}:#{packet['Dport']} (elapsed_time: #{elapsed_time}, size: #{packet['Size']}, rtt: #{rtt})"
      end
    when 18 # syn, ack
      rtt = '%.10f' % ( packet['Timestamp'] - packets[i - 1]['Timestamp'] )
      elapsed_time = '%.10f' % ( packet['Timestamp'] - start_timestamp )
      puts "RTT: #{'%.6f' % packet['Timestamp']} #{int2ip(packet['Dst'])}:#{packet['Dport']} > #{int2ip(packet['Src'])}:#{packet['Sport']} (elapsed_time: #{elapsed_time}, size: #{packet['Size']}, rtt: #{rtt})"
    when 24 # psh, ack
      case packet['Direction']
      when 'to'
        acks = packets.select{ |pkt| pkt['Ack'] == packet['Seq'] + packet['Size']}
        acks.each do |pkt|
          rtt = '%.10f' % (pkt['Timestamp'] - packet['Timestamp'] )
          elapsed_time = '%.10f' % ( pkt['Timestamp'] - start_timestamp )
          puts "ADU: #{'%.6f' % pkt['Timestamp']} #{int2ip(pkt['Dst'])}:#{pkt['Dport']} < #{int2ip(pkt['Src'])}:#{pkt['Sport']} (elapsed_time: #{elapsed_time}, size: #{pkt['Size']}, rtt: #{rtt})"
        end
      end
    end
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
    populate_tcp_sessions(db)
    sessions_stm = db.prepare "SELECT * FROM Sessions"
    sessions = sessions_stm.execute

    sessions.each do |session|
      puts "====== session: #{session['Id']} ======="
      packets_stm = db.prepare "SELECT * FROM Packets where Session='#{session['Id']}'"
      packets = packets_stm.execute

      follow_session(packets.to_a)
    end

  rescue Docopt::Exit => e
    puts e.message
  end
end

main
