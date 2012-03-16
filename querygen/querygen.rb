#!/usr/bin/env ruby
require("gsl")
require("getoptlong")
require 'optparse'
require 'json'
require 'data-pdf'
require 'binary-random-param'
require 'dns-query'
require 'name-generator'

include GSL

# TODO
# edns_buffer_size is generated as string
# recursive is an integer, check for boolean values

options = {}

valid_ratio = 0.0..1.0

optparse = OptionParser.new do|opts|
    # Set a banner, displayed at the top
    # of the help screen.
    opts.banner = "Usage: querygen.rb [options] "

    # Define the options, and what they do
    options[:num_queries] = 100
    opts.on( '-nMANDATORY',
             '--num-queries=MANDATORY',
             OptionParser::DecimalInteger,
             'Number of queries to generate' ) do|nq|
        # Validate is a positive number
        if (nq <= 0) 
            raise ArgumentError, "Number of queries must be higher than 0"
        end
        options[:num_queries] = nq
    end

    options[:edns_ratio] = 0
    opts.on( '-eMANDATORY',
             '--edns-ratio=MANDATORY',
             Float,
             'Fraction of queries with EDNS support' ) do|edns_ratio|
        if (!valid_ratio.include?(edns_ratio)) then
            raise ArgumentError, "EDNS ratio out of range!"
        end
        options[:edns_ratio] = edns_ratio
    end

    options[:dobit_ratio] = 0
    opts.on( '-dMANDATORY',
             '--do-bit-ratio=MANDATORY',
             Float,
             'Fraction of EDNS queries with DO bit on' ) do|dobit_ratio|
        if (!valid_ratio.include?(dobit_ratio)) then
            raise ArgumentError, "DO bit ratio out of range!"
        end
        options[:dobit_ratio] = dobit_ratio
    end

    options[:recurs_ratio] = 0
    opts.on( '-rMANDATORY',
             '--recursive-ratio=MANDATORY',
             Float,
             'Fraction of recursive queries' ) do|recurs_ratio|
        if (!valid_ratio.include?(recurs_ratio)) then
            raise ArgumentError, "recursive ratio out of range!"
        end
        options[:recurs_ratio] = recurs_ratio
    end

    options[:hit_ratio] = 1
    opts.on( '-qMANDATORY',
             '--hit-ratio=MANDATORY',
             Float,
             'Fraction of queries for existing names' ) do|ratio|
        if (!valid_ratio.include?(ratio)) then
            raise ArgumentError, "hit names ratio out of range!"
        end
        options[:hit_ratio] = ratio
    end

    options[:edns_buf_sz_file] = nil
    opts.on( '-zMANDATORY', '--edns-buffer-size-file=MANDATORY', 'file with the EDNS buffer size distribution' ) do|edns_buf_sz_file|
        if (!FileTest::exist?(edns_buf_sz_file)) then
            raise ArgumentError, "EDNS buffer size file doesn't exist"
        end
        options[:edns_buf_sz_file] = edns_buf_sz_file
    end

#    [ "-t", "--qtype-distrib-file", GetoptLong::REQUIRED_ARGUMENT ]

    options[:qtype_file] = nil
    opts.on( '-tMANDATORY', '--qtype-distrib-file=MANDATORY', 'file with the qtype distribution' ) do|qtype_file|
        if (!FileTest::exist?(qtype_file)) then
            raise ArgumentError, "qtype distrib file doesn't exist"
        end
        options[:qtype_file] = qtype_file
    end

    options[:hit_file] = nil
    opts.on( '-iMANDATORY', '--hit-names-file=MANDATORY', 'file with names that exist' ) do|hit_file|
        if (!FileTest::exist?(hit_file)) then
            raise ArgumentError, "hit names file doesn't exist"
        end
        options[:hit_file] = hit_file
    end

    options[:miss_file] = nil
    opts.on( '-mMANDATORY', '--miss-names-file=MANDATORY', 'file with names that dont exist' ) do|miss_file|
        if (!FileTest::exist?(miss_file)) then
            raise ArgumentError, "miss names file doesn't exist"
        end
        options[:miss_file] = miss_file
    end

    # This displays the help screen, all programs are
    # assumed to have this option.
    opts.on( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
    end
end

optparse.parse!

# p "Options:", options
# p "ARGV:", ARGV

if (options[:dobit_ratio] > options[:edns_ratio]) then
    raise ArgumentError, "DO bit ratio has to be smaller than EDNS ratio"
end


# Validate a minimum of parameters has been given
if (nil == options[:qtype_file]) then
    raise ArgumentError, "A qtype file must be provided"
end

if (nil == options[:hit_file]) then
    raise ArgumentError, "A file with the hit names must be provided"
end
if (nil == options[:miss_file]) then
    raise ArgumentError, "A file with the miss names must be provided"
end

num_queries = options[:num_queries]
edns_ratio  = 0

# Data generators
# QNAME generator
qname_gen = NameGenerator.new(
                options[:hit_ratio],
                options[:hit_file],
                options[:miss_file]
            )

# QTYPE generator
qtype_gen = DataPDF.new
qtype_gen.read(options[:qtype_file])

# EDNS Buffer size generator
edns_buf_gen = DataPDF.new
if (options[:edns_ratio] > 0) then
    if (nil == options[:edns_buf_sz_file]) then
        raise ArgumentError, "A EDNS buffer size file must be provided"
    end
    edns_buf_gen.read(options[:edns_buf_sz_file])
end

# Binary parameters
recurs_gen = BinaryRandomParam.new(options[:recurs_ratio])
edns_gen   = BinaryRandomParam.new(options[:edns_ratio])
dobit_gen  = BinaryRandomParam.new(options[:dobit_ratio])

# Container for the queries to generate
dns_query_list = Array.new

for i in 1..num_queries do
#    print "#{i}: "

    qtype = qtype_gen.get_sample
    qname = qname_gen.get_name

    dns_query = DnsQuery.new(qname, qtype)
    
    edns_support = edns_gen.get_var
    if (1 == edns_support) then
        dns_query.edns_buffer_sz = edns_buf_gen.get_sample
        dns_query.do_bit = dobit_gen.get_var
    end

    dns_query.recursive = recurs_gen.get_var

    dns_query_list.push(dns_query)
end

puts JSON.pretty_generate({ :querylist => dns_query_list,
                            :options   => options })

# Subroutines to read data

