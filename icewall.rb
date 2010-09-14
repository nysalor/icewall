#!/usr/bin/ruby
require 'optparse'

# default path
@blacklist = '/etc/deny.list'
@whitelist = '/etc/allow.list'

@denyaddr = []
@allowaddr = []
@pattern = 'ssh from \d+\.\d+\.\d+\.\d+ exceeded counts/min'

opt = OptionParser.new

opt.on('-d DENY_ADDRESSES') {|var| @denyaddr << var }
opt.on('-a ALLOW_ADDRESSES') {|var| @allowaddr << var }
opt.on('-b BLACKLIST') {|var| @blacklist = var }
opt.on('-w WHITELST') {|var| @whitelist = var }
opt.on('-m LOGFILE') {|var| @logfile = var }
opt.on('-p PATTERN') {|var| @pattern = var.sub(/^\//,'').sub(/\/$/,'') }

opt.parse!(ARGV)

if @logfile
  log = File.new
  log.open(@logfile) rescue STDERR.puts "Error: #$!"
  regexp_line = Regexp.new(@pattern)
  regexp_addr = Regexp.new('\d+\.\d+\.\d+\.\d+')
  log.each do |line|
    if regexp_line.match(line)
      @denyaddr += regexp_addr.match(line).to_a
    end
  end
end
