class DnsQuery
    # Each query has a Question and Options
    attr_accessor :qname
    attr_accessor :qtype
    attr_accessor :qclass
    attr_accessor :recursive
    attr_reader   :edns_version
    attr_accessor :edns_buffer_sz
    attr_accessor :do_bit
    attr_reader   :edns_support

    def initialize(*args)
        @qtype = 'A'
        @qclass = 'IN'
        if (args.length > 0)
            if (args.length > 1)
                @qtype = args[1]
                if (args.length > 2)
                    @qclass = args[2]
                end
            end
        else
            raise ArgumentError.new("Must provide at least a name")
        end
        @qname = args[0]
        @edns_support = false
        @edns_version = 0
        @recursive = false
        @edns_buffer_sz = 4096
        @do_bit = false
    end

    def edns_buffer_sz=(size)
        @edns_buffer_sz = size
        @edns_support = true
    end

    def do_bit=(bit)
        @do_bit = bit
        @edns_support = true
    end

    def to_json(*a)
        values = {
            'qname'  => @qname.to_s,
            'qtype'  => @qtype.to_s,
            'qclass' => @qclass.to_s,
            'recursive' => @recursive
        }
        if (@edns_support) then
            values.merge!(
                {
                    'edns_version' => @edns_version,
                    'edns_buffer_size' => @edns_buffer_sz.to_i,
                    'do_bit'           => @do_bit
                })
        end
        
        values.to_json(*a)
    end

end
