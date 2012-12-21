#!/usr/bin/env ruby
#
# Snoopy - A lightweight bypass censorship system for HTTP
# Copyright (C) 2012- Changli Gao <xiaosuo@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

require 'thread'
require 'net/http'
require 'optparse'

options = {}
opt_pasr = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"

  opts.separator("")
  opts.separator("Options:")

  opts.on("-b", "--background", "Run as a background daemon") do |b|
    options[:background] = true
  end

  opts.on('-H', '--host HOST', 'Server host') do |h|
    options[:host] = h
  end

  opts.on("-h", "--help", "Show this message") do |h|
    puts opts
    exit
  end
end
opt_pasr.parse!(ARGV)
if ARGV.length > 0
  puts opt_pasr
  exit(false)
end
if options[:host]
  HOST = options[:host]
else
  HOST = '127.0.0.1'
end

WHITE_LIST = '/etc/snoopy/snoopy-fqdn-white.list'
GRAY_LIST = '/etc/snoopy/snoopy-fqdn-gray.list'
BLACK_LIST = '/etc/snoopy/snoopy-fqdn-black.list'
INPUT_LOG_FN = '/var/log/snoopy-fqdn.log'
WHITE_URI = "http://#{HOST}/getlist.asp?listtype=1"
GRAY_URI = "http://#{HOST}/getlist.asp?listtype=3"
BLACK_URI = "http://#{HOST}/getlist.asp?listtype=2"
GRAY_POST_URI = "http://#{HOST}/postlist.asp?type=2"
SYNC_INTERVAL = 10 * 60 # 10 minutes

module FQDN
  class Label
    attr_accessor :mark

    def initialize
      @sub_label = {}
    end

    def [](label)
      @sub_label[label]
    end

    def []=(label, sub)
      @sub_label[label] = sub
    end
  end

  class Database
    def initialize(fn)
      @root = FQDN::Label.new
      IO.foreach(fn) do |line|
        insert(line.rstrip)
      end
    end

    def insert(fqdn)
      cur = @root
      fqdn.split(/\./).reverse.each do |label|
        cur[label] ||= FQDN::Label.new
        cur = cur[label]
      end
      cur.mark = true
    end

    def query(fqdn)
      cur = @root
      fqdn.split(/\./).reverse.each do |label|
        return false unless cur = cur[label]
        return true if cur.mark
      end
      false
    end
  end
end

class LogPoster
  def initialize(uri)
    @queue = Queue.new
    Thread.new do
      uri = URI.parse(uri)
      loop do
        fqdn = @queue.shift
	# Why not use post_form, because post_form doesn't reserve query
	req = Net::HTTP::Post.new(uri.path + '?' + uri.query)
	req.form_data = {'fqdn' => fqdn}
	Net::HTTP.new(uri.host, uri.port).start do |http|
	  http.request(req)
	end
      end
    end
  end

  def log(fqdn)
    @queue << fqdn
  end
end

# Create the input log file as a pipe
unless File.pipe?(INPUT_LOG_FN)
  File.unlink(INPUT_LOG_FN) if File.exist?(INPUT_LOG_FN)
  `mkfifo #{INPUT_LOG_FN}`
  unless File.pipe?(INPUT_LOG_FN)
    puts 'failed to create ' + INPUT_LOG_FN
    exit(1)
  end
end

if options[:background]
  exit!(0) if fork
  Process.setsid
  exit!(0) if fork
  Dir.chdir('/')
  File.umask(0)
  STDIN.reopen('/dev/null')
  STDOUT.reopen('/dev/null', 'w')
  STDERR.reopen('/dev/null', 'w')
end

# Create two log posters for black and gray logs
gray_log = LogPoster.new(GRAY_POST_URI)
white_list = nil
gray_list = nil
black_list = nil

sync_lists = lambda do
  content = Net::HTTP.get(URI.parse(WHITE_URI))
  File.open(WHITE_LIST, 'w'){|file| file.write(content)}
  white_list = FQDN::Database.new(WHITE_LIST)
  content = Net::HTTP.get(URI.parse(GRAY_URI))
  File.open(GRAY_LIST, 'w'){|file| file.write(content)}
  list = {}
  IO.foreach(GRAY_LIST){|l| list[l.rstrip] = true}
  gray_list = list
  content = Net::HTTP.get(URI.parse(BLACK_URI))
  File.open(BLACK_LIST, 'w'){|file| file.write(content)}
  black_list = FQDN::Database.new(BLACK_LIST)
end

sync_lists.call

# Sync the lists every SYNC_INTERVAL
syncer = Thread.new do
  loop do
    sleep(SYNC_INTERVAL)
    sync_lists.call
  end
end

loop do
  File.open(INPUT_LOG_FN) do |file|
    while line = file.gets
      # Drop partial logs
      break unless line[-1, 1] == "\n"
      fqdn = line.rstrip

      # Do nothing with the FQDN in the white list
      next if white_list.query(fqdn)

      next if black_list.query(fqdn)

      unless gray_list[fqdn]
        gray_list[fqdn] = true
        gray_log.log(fqdn)
      end
    end
  end
end
