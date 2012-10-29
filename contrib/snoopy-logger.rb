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

require 'optparse'

LOG_DIR = '/var/log/snoopy.log.d'
LOG_FN = '/var/log/snoopy.log'

options = {:background => false}
opt_pasr = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"

  opts.separator("")
  opts.separator("Options:")

  opts.on("-b", "--background", "Run as a background daemon") do |b|
    options[:background] = true
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

Dir.mkdir(LOG_DIR) unless File.directory?(LOG_DIR)

unless File.pipe?(LOG_FN)
  File.unlink(LOG_FN) if File.exist?(LOG_FN)
  `mkfifo #{LOG_FN}`
  unless File.pipe?(LOG_FN)
    puts 'failed to create ' + LOG_FN
    exit(false)
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

require 'date'

out = nil
cur_date = nil
while true
  File.open(LOG_FN, 'r') do |f|
    while l = f.gets
      # drop partial logs, as them indicate snoopy exits exceptionally.
      break unless l[-1, 1] == "\n"
      # save logs by the local time
      l.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/)
      date = Time.utc($1, $2, $3, $4, $5, $6).localtime.strftime('%F')
      if cur_date != date
        cur_date = date
        out.close if out
        out = File.new(File.join(LOG_DIR, date + '.log'), 'a')
      end
      if out.write(l) != l.length
        puts 'failed to write log'
        exit(false)
      end
    end
  end
  puts 'snoopy exits. try again'
end
