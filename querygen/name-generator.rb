#!/usr/bin/env ruby
require("gsl")
include GSL

class NameGenerator
    @hit_prob
    @hit_names
    @miss_names
    @@valid_prob = 0.0..1.0

    def initialize(prob,hit_filename,miss_filename)
        @rng = Rng.alloc(GSL::Rng::RANLXD2, Process.pid)
        # Validate prob is in a valid range
        if (!@@valid_prob.include?(prob)) then
            raise ArgumentError, "#{prob} is not a valid value"
        end
        # Validate the files provided exist
        if (!FileTest::exist?(hit_filename)) then
            raise ArgumentError, "#{hit_filename} doesn't exist"
        end
        if (!FileTest::exist?(miss_filename)) then
            raise ArgumentError, "#{miss_filename} doesn't exist"
        end
        @hit_prob = prob

        # Read the files
        @hit_names  = Array.new
        file_h = File.new(hit_filename)
        file_h.each do |line|
            line.chomp!
            @hit_names.push line
        end
        @miss_names = Array.new
        file_h = File.new(miss_filename)
        file_h.each do |line|
            line.chomp!
            @miss_names.push line
        end
    end

    def get_random_item(array)
        elem_num = array.size
        rnd_idx = elem_num*@rng.uniform()

        array[rnd_idx]
    end

    private :get_random_item

    def get_name
        random_no = @rng.uniform()
        name = nil
        if (random_no <= @hit_prob) then
            name = get_random_item(@hit_names)
        else
            name = get_random_item(@miss_names)
        end

        name
    end

end
