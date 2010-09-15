#!/usr/bin/ruby

require 'optparse'
require 'icewall'
require 'yaml'

class Hash
  def symbolize(obj)
    self.each do |key, value|
      if value.is_a?(Hash)
        value_obj = Hash.new
        value.symbolize(value_obj)
        obj[key.to_sym] = value_obj
      else
        obj[key.to_sym] = value
      end
    end
  end
end

def logger(*args)
  puts(args.join(' ')) unless @quiet
end

# Default path
@blacklist_file = '/etc/deny.list'
@whitelist_file = '/etc/allow.list'

@pattern = 'from \d+\.\d+\.\d+\.\d+ exceeded counts/min'

@denyaddr = []
@allowaddr = []
@logfiles = []
@count = 1

opt = OptionParser.new

opt.on('-d DENY_ADDRESSES') {|var| @denyaddr << var }
opt.on('-a ALLOW_ADDRESSES') {|var| @allowaddr << var }
opt.on('-b BLACKLIST') {|var| @blacklist_file = var }
opt.on('-w WHITELST') {|var| @whitelist_file = var }
opt.on('-m LOGFILE') {|var| @logfiles << var }
opt.on('-p PATTERN') {|var| @pattern = var.sub(/^\//,'').sub(/\/$/,'') }
opt.on('-c COUNT') {|var| @count = var.to_i if var.to_i > 0}
opt.on('-f RECIPE_FILE') {|var| @recipe_file = var }

opt.on('-r') { @remove = true }
opt.on('-s') { @stdin = true }
opt.on('-n') { @no_save = true }
opt.on('-q') { @quiet = true }

opt.parse!(ARGV)

@icewall = Icewall.new(:blacklist => @blacklist_file, :whitelist => @whitelist_file)

if @no_save
  logger('*** non-executable run ***')
end

if @remove
  unless @allowaddr.empty?
    @icewall.disallow(@allowaddr)
    logger('removed from whitelist: ', @allowaddr)
    @allowaddr.clear
  end

  unless @denyaddr.empty?
    @icewall.undeny(@denyaddr)
    logger('removed from blacklist: ', @denyaddr)
    @denyaddr.clear
  end
end

@recipe = {}
if @recipe_file
  File.open(@recipe_file) do |io|
    YAML.load_documents(io) {|y| y.symbolize(@recipe) }
  end
  @blacklist_file = (@recipe[:blacklist] || @blacklist_file)
  @whitelist_file = (@recipe[:whitelist] || @whitelist_file)
else
  @recipe[:recipe] = {
    :default => {
      :pattern => @pattern,
      :count => @count,
    }
  }
end

if @logfiles.flatten.empty? && @stdin
  @log = ARGF.read
else
  @log = @logfiles.flatten.map{|logfile| File.open(logfile).read}.join
end

@recipe[:recipe].each do |name, params|
  logger("processing #{name}...")

  addresses = Hash.new(0)
  regexp = Regexp.new(params[:pattern])
  @log.each do |line|
    line.chomp!
    if regexp.match(line)
      line.ip_scan.each do |addr|
        addresses[addr] += 1
      end
    end
  end
  deny = []
  addresses.each do |addr, num|
    if num >= params[:count]
      logger("#{addr} violated #{num} times.")
      deny << addr
    end
  end
  @denyaddr = @denyaddr | deny
end

@icewall.allow(@allowaddr)
@icewall.deny(@denyaddr)
@icewall.sort!

logger('added to blacklist:', @denyaddr.uniq) unless @denyaddr.empty?
logger('added to whitelist:', @allowaddr.uniq) unless @allowaddr.empty?

unless @no_save
  @icewall.save!
end
