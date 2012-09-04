#!/usr/bin/ruby
#

require 'optparse'
require 'socket'
include Socket::Constants

options = {:host => "127.0.0.1", :port => 80, :convert => false}
OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] REQ_FILE"

  opts.separator ""
  opts.separator "Options:"

  opts.on("-H", "--host HOST", "Host") do |h|
    options[:host] = h
  end

  opts.on("-p", "--port PORT", "Port") do |p|
    options[:port] = p.to_i
  end

  opts.on("-c", "--convert", "Convert LF to CRLF") do |c|
    options[:convert] = true
  end

  opts.on("-h", "--help", "Show this message") do |h|
    puts opts
    exit
  end
end.parse!(ARGV)

if ARGV.length != 1
  puts "Usage: #{$0} [options] REQ_FILE"
  exit(1)
end

req = IO.read(ARGV[0])
req.gsub!(/\n/, "\r\n") if options[:convert]
sock = TCPSocket.new(options[:host], options[:port])
sock.write(req)
res = sock.read()
puts res
