require 'bit-struct'
require 'pcap_simple/version'

module PcapSimple
  PCAP_HEADER_LEN=   ((5*32 + 2*16)/8)
  PACKET_HEADER_LEN= ((4*32)/8)

  class PcapFile
    attr_accessor :file_name
    attr_reader   :header
    include Enumerable
    def initialize(*args)
      Hash[*args].each {|k,v| self.send("%s="%k,v)}
      raise ArgumentError, "need to specify file_name" if file_name.nil?
      header_raw=File.read(file_name, PCAP_HEADER_LEN)
      @header=PcapHeader.new(header_raw)
      yield self if block_given?
    end

    def each(&block)
      File.open(file_name,"r") do |file|
        file.seek(PCAP_HEADER_LEN)
        loop do
          header_data=file.read(PACKET_HEADER_LEN)
          break if (header_data.nil? || header_data.length < PACKET_HEADER_LEN)
          header=PcapRecord.new(header_data)
          raw=file.read(header.incl_len)
          break if (raw.nil? || raw.length < header.incl_len)
          packet=Packet.new(:raw_data=>raw,:header=>header)

          yield packet
        end
      end
    end
  end
  class Packet
    attr_accessor :raw_data, :header
    attr_reader   :ethernet, :ip

    def initialize(*args)
      Hash[*args].each {|k,v| self.send("%s="%k,v)}
      raise ArgumentError, "need to specify raw_data" if raw_data.nil?
      @ethernet=Ethernet.new(raw_data)
      @ip      =IP.new(@ethernet.data)
    end
    def time
      Time.at(header.ts_sec)
    end
  end

  class PcapHeader < BitStruct
    default_options :endian=>:native
    unsigned  :magic_number,  32, "Magic Number"
    unsigned  :version_major, 16, "Major Version Number"
    unsigned  :version_minor, 16, "Minor Version Number"
    signed    :thiszone,      32, "GMT to local offset"
    unsigned  :sigfigs,       32, "Timestamp Accuracy"
    unsigned  :snaplen,       32, "max octets per captured packet"
    unsigned  :network,       32, "Datalink Capture Type"
  end

  class PcapRecord < BitStruct
    default_options :endian=>:native
    unsigned  :ts_sec,    32,     "Timestamp Seconds"
    unsigned  :ts_usec,   32,     "Timestamp Microseconds"
    unsigned  :incl_len,  32,     "Octets included in file"
    unsigned  :orig_len,  32,     "Octets in original packet"
  end

  class Ethernet < BitStruct
    hex_octets :enet_dst,  48,     "Source MAC"
    hex_octets :enet_src,  48,     "Destination MAC"
    unsigned   :enet_type, 16,     "Ethertype or length"
    rest       :data
  end

  class IP < BitStruct
    unsigned    :ip_v,     4,     "Version"
    unsigned    :ip_hl,    4,     "Header length"
    unsigned    :ip_tos,   8,     "TOS"
    unsigned    :ip_len,  16,     "Length"
    unsigned    :ip_id,   16,     "ID"
    unsigned    :ip_off,  16,     "Frag offset"
    unsigned    :ip_ttl,   8,     "TTL"
    unsigned    :ip_p,     8,     "Protocol"
    unsigned    :ip_sum,  16,     "Checksum"
    octets      :ip_src,  32,     "Source addr"
    octets      :ip_dst,  32,     "Dest addr"
    rest        :data,        "Body of message"

    note "     rest is application defined message body"

    initial_value.ip_v    = 4
    initial_value.ip_hl   = 5
  end

  class UDP < BitStruct
    unsigned    :udp_src,    16,     "Source Port"
    unsigned    :udp_dst,    16,     "Destination Port"
    unsigned    :udp_len,    16,     "Datagram Length"
    unsigned    :udp_chksum, 16,     "Datagram Checksum"
    rest        :data,            "UDP Data"
  end

end
