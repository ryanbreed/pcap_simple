# DATE: Feb 9, 2011
# CREATED BY RYAN BREED
#
require 'rubygems'
require 'bit-struct'

module PcapSimple
  PCAP_HEADER_LEN=   ((5*32 + 2*16)/8)
  PACKET_HEADER_LEN= ((4*32)/8)
  VERSION=File.read(File.join(File.expand_path(File.dirname(__FILE__)),'..','VERSION'))

  class PcapFile
    attr_accessor :file_name
    attr_reader   :file, :header
    include Enumerable
    def initialize(*args)
      Hash[*args].each {|k,v| self.send("%s="%k,v)}
      raise ArgumentError, "need to specify file_name" if file_name.nil?
      @file=File.open(file_name,"r")
      @header=PcapHeader.new(file.read(PCAP_HEADER_LEN))
      yield self if block_given?
    end
    alias :new :open
    
    def each(&block)
      file.seek(PCAP_HEADER_LEN)
      loop do
        header_data=file.read(PACKET_HEADER_LEN)
        break if (header_data.nil? || header_data.length < PACKET_HEADER_LEN)
        header=PcapRecord.new(header_data)
        raw=file.read(header.incl_len)
        break if (raw.nil? || raw.length < header.incl_len)
        packet=Packet.new(:raw_data=>raw,:header=>header)

        yield packet unless packet.datagram.nil?
      end
    end
  end
  class Packet
    attr_accessor :raw_data, :header
    attr_reader   :ethernet, :ip, :datagram
    
    def initialize(*args)
      Hash[*args].each {|k,v| self.send("%s="%k,v)}
      raise ArgumentError, "need to specify raw_data" if raw_data.nil?
      @ethernet=Ethernet.new(raw_data)
      @ip      =IP.new(@ethernet.data)
      case ip.ip_p
        when 17
          @datagram=UDP.new(ip.data)
      end
    end
    def udp_data
      datagram.data
    end
    def src
      ip.ip_src
    end
    def dst
      ip.ip_dst
    end
    def ip_id
      ip.ip_id
    end
    def sport
      datagram.sport
    end
    def dport
      datagram.dport
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
    hex_octets :mac_dst,  48,     "Source MAC"
    hex_octets :mac_src,  48,     "Destination MAC"
    unsigned   :ethertype,16,     "Ethertype or length"
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
    unsigned    :sport,   16,     "Source Port"
    unsigned    :dport,   16,     "Destination Port"
    unsigned    :length,  16,     "Datagram Length"
    unsigned    :checksum,16,     "Datagram Checksum"
    rest        :data,            "UDP Data"
  end

end