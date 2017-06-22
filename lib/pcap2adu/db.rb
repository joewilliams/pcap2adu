module Pcap2adu
  class Database

    def self.create_db()
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

    def self.create_packet_record(db, pcap_obj)
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

  end
end
