#!/usr/bin/ruby

require 'optparse'
require 'icewall'

def logger(*args)
  puts(args.join(' ')) unless @quiet
end

def logparser(*logs)
  logs.map{|log| log.split(/\n/)}.flatten.each do |line|
    line.chomp!
    if @regexp_line.match(line)
      line.ip_scan.each do |addr|
        @icewall.deny(addr)
        @denyaddr << addr
      end
    end
  end
end

# default path
@blacklist_file = '/etc/deny.list'
@whitelist_file = '/etc/allow.list'

@pattern = 'from \d+\.\d+\.\d+\.\d+ exceeded counts/min'

@denyaddr = []
@allowaddr = []
@logfiles = []

opt = OptionParser.new

opt.on('-d DENY_ADDRESSES') {|var| @denyaddr << var }
opt.on('-a ALLOW_ADDRESSES') {|var| @allowaddr << var }
opt.on('-r') { @remove = true }
opt.on('-b BLACKLIST') {|var| @blacklist_file = var }
opt.on('-w WHITELST') {|var| @whitelist_file = var }
opt.on('-m LOGFILE') {|var| @logfiles << var }
opt.on('-p PATTERN') {|var| @pattern = var.sub(/^\//,'').sub(/\/$/,'') }
opt.on('-s') { @stdin = true }
opt.on('-n') { @no_save = true }
opt.on('-q') { @quiet = true }

opt.parse!(ARGV)

@icewall = Icewall.new(:blacklist => @blacklist_file, :whitelist => @whitelist_file)
@regexp_line = Regexp.new(@pattern)

if @no_save
  logger('*** non-executable run ***')
end

unless @allowaddr.empty?
  if @remove
    @icewall.disallow(@allowaddr)
    logger('removed from whitelist: ', @allowaddr)
    @allowaddr = []
  else
    @icewall.allow(@allowaddr)
  end
end

unless @denyaddr.empty?
  if @remove
    @icewall.undeny(@denyaddr)
    @denyaddr = []
    logger('removed from blacklist: ', @denyaddr)
    @allowaddr = []
  else
    @icewall.deny(@denyaddr)
  end
end

if @logfiles.empty? && @stdin
  logparser(ARGF.read)
else
  @logfiles.each do |logfile|
    logparser(File.open(logfile).read)
  end
end

@icewall.sort!

logger('added to blacklist:', @denyaddr.uniq) unless @denyaddr.empty?
logger('added to whitelist:', @allowaddr.uniq) unless @allowaddr.empty?

unless @no_save
  @icewall.save!
end
