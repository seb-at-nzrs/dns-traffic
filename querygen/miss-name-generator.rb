#!/usr/bin/env ruby
require("gsl")
require("optparse");

require 'data-pdf'

def random_string(size = 8)
    chars = (('a'..'z').to_a + ('0'..'9').to_a)

    (1..size).collect{|a| chars[rand(chars.size)] }.join
end

options = {}

optparse = OptionParser.new do|opts|
    opts.banner = "Usage: miss-name-generator.rb [options] "

    options[:n] = 100
    opts.on( '-nMANDATORY', '--number=MANDATORY', 
            OptionParser::DecimalInteger,
            "Number of names to generate (default=#{options[:n]})" ) do |n|
        if (n <= 0) 
            raise ArgumentError, "Number of names must be positive"
        end
        options[:n] = n
    end

    options[:l] = 10
    opts.on( '-lMANDATORY', '--length=MANDATORY', 
            OptionParser::DecimalInteger,
            "Length of the random string to generate (default=#{options[:l]})" ) do |l|
        if (l <= 0) 
            raise ArgumentError, "Length must be positive"
        end
        options[:l] = l
    end
   
    options[:e] = nil
    opts.on( '-eMANDATORY', '--existing=MANDATORY', 
            'File with a list of names that do exists' ) do |hit_name_file|
        if (!FileTest::exist?(hit_name_file)) then
            raise ArgumentError, "Existing name file doesn't exist"
        end
        options[:e] = hit_name_file
    end

    opts.on( '-h', '--help', 'Display the help screen' ) do
        puts opts
        exit
    end
end

optparse.parse!

if (nil == options[:e]) then
    raise ArgumentError, "Existing name file must be provided"
end

# Read the list of name that do exist
valid_name = Array.new
file_h = File.new(options[:e])
file_h.each do |line|
    line.chomp!
    valid_name.push line
end

sld_pdf = DataPDF.new
sld_pdf.read("sld-distrib.txt")
name_cnt = 0
until name_cnt == options[:n] do
    # XXX: Need to validate the name created is not a existent name
    candidate = random_string(options[:l]) + "." + sld_pdf.get_sample.to_s + "."
    if ((valid_name & [ candidate ]).empty?) then
        puts candidate
        name_cnt += 1
    end
end
