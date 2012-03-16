#!/usr/bin/env ruby
require("gsl")

require 'binary-random-param'

bit_gen = BinaryRandomParam.new(0.7)
for i in 0...100 do
    p bit_gen.get_var.to_s
end

