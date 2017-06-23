require 'rubygems'
require 'packetfu'
require 'docopt'
require 'sqlite3'
require 'securerandom'
require 'ipaddr'
require 'ffi/pcap'
require 'ffi/packets'

__DIR__ = File.dirname(__FILE__)

$LOAD_PATH.unshift __DIR__ unless
  $LOAD_PATH.include?(__DIR__) ||
  $LOAD_PATH.include?(File.expand_path(__DIR__))

require 'pcap2adu/version'
require 'pcap2adu/cli'
require 'pcap2adu/monkeypatch'
require 'pcap2adu/utils'
require 'pcap2adu/db'

module Pcap2adu
  class << self

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
        Pcap2adu::Database::create_packet_record(db, pkt)
      end
    end

    def get_start_ts(packets)
      packets.select{ |pkt| pkt['Flags'] == 2 && pkt['Ack'] == 0 }.first['Timestamp']
    end

    def syn(packet, packets)
      puts "SYN: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} > #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']}"
    end

    def ack(packet, packets)
      case packet['Direction']
      when 'to'
        syn_ack = packets.select{ |pkt| pkt['Flags'] == 18 && pkt['Seq'] == packet['Ack'] - 1 }.first
        if syn_ack
          puts "SEQ: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} > #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']}"
        end
      end
    end

    def syn_ack(packet, packets)
      syn = packets.select{ |pkt| pkt['Flags'] == 2 && pkt['Seq'] == packet['Ack'] - 1 && pkt['Ack'] == 0 }.first
      rtt = '%.10f' % ( packet['Timestamp'] - syn['Timestamp'] )
      elapsed_time = '%.10f' % ( packet['Timestamp'] - get_start_ts(packets) )
      puts "RTT: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']} < #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} (elapsed_time: #{elapsed_time}, rtt: #{rtt}, size: #{packet['Size']})"
    end

    def data_packets(packet, packets)
      case packet['Direction']
      when 'to'
        ack = packets.select{ |pkt| pkt['Flags'] == 16 && pkt['Size'] == 0 && pkt['Ack'] == packet['Ack']}.first
        rtt = '%.10f' % ( packet['Timestamp'] - ack['Timestamp'] )
        elapsed_time = '%.10f' % ( packet['Timestamp'] - get_start_ts(packets) )
        puts "ADU: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} > #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']} (elapsed_time: #{elapsed_time}, rtt: #{rtt}, size: #{packet['Size']})"
      when 'from'
        ack = packets.select{ |pkt| pkt['Ack'] == packet['Seq'] - @acc }.first
        rtt = '%.10f' % ( packet['Timestamp'] - ack['Timestamp'] )
        elapsed_time = '%.10f' % ( packet['Timestamp'] - get_start_ts(packets) )
        puts "ADU: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']} < #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} (elapsed_time: #{elapsed_time}, rtt: #{rtt}, size: #{packet['Size']})"
        @acc = packet['Size'] + @acc
      end
    end

    def fin(packet, packets)
      case packet['Direction']
      when 'from'
        elapsed_time = '%.10f' % ( packet['Timestamp'] - get_start_ts(packets) )
        puts "END: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} > #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']} (elapsed_time: #{elapsed_time})"
      end
    end

    def reset(packet, packets)
      case packet['Direction']
      when 'from'
        elapsed_time = '%.10f' % ( packet['Timestamp'] - get_start_ts(packets) )
        puts "END: #{'%.6f' % packet['Timestamp']} #{Pcap2adu::Utils.int2ip(packet['Src'])}:#{packet['Sport']} > #{Pcap2adu::Utils.int2ip(packet['Dst'])}:#{packet['Dport']} (elapsed_time: #{elapsed_time})"
      end
    end

    def follow_session(packets)
      @acc = 0

      packets.each_with_index do |packet, i|
        case packet['Flags']
        when 2 # syn
          syn(packet, packets)
        when 16 # ack
          if packet['Size'] > 0
            data_packets(packet, packets)
          else
            ack(packet, packets)
          end
        when 18 # syn, ack
          syn_ack(packet, packets)
        when 17 # ack, fin
          fin(packet, packets)
        when 1 # fin
          fin(packet, packets)
        when 4 # reset
          # avoid duplicate resets
          if packet == packets.last
            reset(packet, packets)
          end
        else
          if packet['Size'] > 0
            data_packets(packet, packets)
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

        db = Pcap2adu::Database::create_db()
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

  end
end
