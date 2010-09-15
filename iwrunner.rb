#!/usr/bin/ruby

Version = "0.2"

require 'optparse'
require 'yaml'
require 'icewall'

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

opt.on('-d', '--deny=DENY_ADDRESSES', String, 'specify IP addresses to deny.') {|var| @denyaddr << var }
opt.on('-a', '--allow=ALLOW_ADDRESSES', String, 'specify IP addresses to allow.') {|var| @allowaddr << var }
opt.on('-b', '--blacklist=BLACKLIST', String, 'specify blacklist file. (default:/etc/deny.list)') {|var| @blacklist_file = var }
opt.on('-w', '--whitelist=WHITELST', String, 'specify whitelist file. (default:/etc/allow.list)') {|var| @whitelist_file = var }
opt.on('-l', '--logfile=LOGFILE', String, 'specify logfile to analyze.') {|var| @logfiles << var }
opt.on('-p', '--pattern=PATTERN', String, 'specify pattern to find violation.') {|var| @pattern = var.sub(/^\//,'').sub(/\/$/,'') }
opt.on('-c', '--count=COUNT', Integer, 'set violation threshold. (default:1)') {|var| @count = var.to_i if var.to_i > 0}
opt.on('-f', '--file=RECIPE', String, 'set recipe file. (YAML format)') {|var| @recipe_file = var }

opt.on('-r', '--remove', 'remove addresses from black/white list.') { @remove = true }
opt.on('-s', '--stdin', 'read log from STDIN.') { @stdin = true }
opt.on('-n', '--non-executable', 'non-executable run. (do not save)') { @no_save = true }
opt.on('-q', '--quiet', 'quiet mode.') { @quiet = true }

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
