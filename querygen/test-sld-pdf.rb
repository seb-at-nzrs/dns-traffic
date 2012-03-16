#!/usr/bin/env ruby
require 'data-pdf'

sld_pdf = DataPDF.new
sld_pdf.read("sld-distrib.txt")
for i in 0...10 do
    p sld_pdf.get_sample.to_s
end
