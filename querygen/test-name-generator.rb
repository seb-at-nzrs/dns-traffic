#!/usr/bin/env ruby
require("gsl")

require 'name-generator'

gen = NameGenerator.new(0.7,"hit-names.txt","miss-names.txt")
for i in 0...100 do
    p gen.get_name.to_s
end

