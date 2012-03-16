#!/usr/bin/env ruby
require("gsl")

require 'data-pdf'


data = DataPDF.new
buffer = DataPDF.new
data.read("qtype.dat")
buffer.read("edns-buffer-size.dat")
for i in 0...100 do
    p data.get_sample.to_s
    p buffer.get_sample.to_s
end

