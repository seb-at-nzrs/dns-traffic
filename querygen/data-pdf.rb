#!/usr/bin/env ruby
require("gsl")
include GSL

class DataPDF
    @histogram
    @@valid_cdf = 0.99..1.01

    def initialize
        @histo_data = Array.new
        @rng = Rng.alloc(GSL::Rng::RANLXD2, Process.pid)
        @key_list = Array.new
        @key_id = 0
    end

    def read(filename)
        file_h = File.new(filename)
        prob_accum = 0
        idx = 0
        file_h.each do |line|
            line.chomp!
            # Skip comments or empty lines
            
            # Each line contain a probability and key
            elem = line.split(/\t/)
            @key_list.push elem[1]
            @key_id += 1
            @histo_data.push({"prob"=>elem[0].to_f,"key"=>elem[1]})
#            p "Accum = #{prob_accum}"
            prob_accum += elem[0].to_f
        end

        # Validate the accumulated prob is near 1
        if (!@@valid_cdf.include?(prob_accum)) then
            raise ArgumentError, "The accumulated probability doesn't sum 1 #{prob_accum}"
        end

        # Initialize the internal histogram with the data read
        @histogram = GSL::Histogram.alloc(@histo_data.size)
        @histogram.set_ranges_uniform(0, @histo_data.size)
        # Iterate over the list of elements and change the size of the
        # bin accordingly
        @histo_data.each_with_index do |elem,i|
            @histogram.accumulate(i,elem["prob"])
        end
#        @histogram.fprintf($stdout)
        @histo_pdf = GSL::Histogram::Pdf.alloc(@histogram)
    end

    def get_sample
        value = @histo_pdf.sample(@rng.uniform()).floor

        @key_list[value]
    end
end
