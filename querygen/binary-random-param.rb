#!/usr/bin/env ruby
require("gsl")
include GSL

class BinaryRandomParam

    def initialize(prob)
        @prob = prob
        @rng = Rng.alloc(GSL::Rng::RANLXD2, Process.pid)
    end

    def get_var
        random_no = @rng.uniform()
        var = 0
        var = 1 if (random_no <= @prob)

        var
    end
end
