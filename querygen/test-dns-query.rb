#!/usr/bin/env ruby

require 'json'
require 'dns-query'


dns_query = DnsQuery.new("version.bind")
dns_query.recursive = false
dns_query.edns_buffer_sz = 512
dns_query.do_bit = true
puts JSON.pretty_generate(dns_query)

query2 = DnsQuery.new("root-servers.org", "SOA")
query2.recursive = true
query2.do_bit = false
puts JSON.pretty_generate(query2)

