class Icewall
  attr_reader :blacklist, :whitelist

  def initialize(*args)
    @blacklist = []
    @whitelist = []
    options = args.first || {}
    @blacklist_file = options[:blacklist]
    @whitelist_file = options[:whitelist]
    load_files
  end

  def deny(*addresses)
    @blacklist  = @blacklist | (addresses.flatten.ip_select - @whitelist)
  end

  def allow(*addresses)
    @whitelist = @whitelist | addresses.flatten.ip_select
  end

  def undeny(*addresses)
    @blacklist  = @blacklist - addresses.flatten.ip_select
  end

  def disallow(*addresses)
    @whitelist = @whitelist - addresses.flatten.ip_select
  end

  def load_files
    load_blacklist
    load_whitelist
  end

  def load_blacklist
    @blacklist = load_file(@blacklist_file)
  end

  def load_whitelist
    @whitelist = load_file(@whitelist_file)
  end

  def sort!
    sort_blacklist!
    sort_whitelist!
  end

  def sort_blacklist
    sortbyaddr(@blacklist).uniq
  end

  def sort_blacklist!
    @blacklist = sort_blacklist
  end

  def sort_whitelist
    sortbyaddr(@whitelist).uniq
  end

  def sort_whitelist!
    @whitelist = sort_whitelist
  end

  def save!
    save_blacklist!
    save_whitelist!
  end

  def save_blacklist!
    save_file(@blacklist_file, @blacklist)
  end

  def save_whitelist!
    save_file(@whitelist_file, @whitelist)
  end

  private
  def load_file(file)
    if file
      File.read(file).split("\n")
    else
      []
    end
  end

  def save_file(file,list)
    f = File.open(file, "w")
    f.flock(File::LOCK_EX)
    f.puts(list)
    f.close
  end

  def sortbyaddr(list)
    list.ip_select.sort_by{|a| a.split(".").map {|c| c.to_i}.pack("C4")}
  end

end

class Array
  def ip_select
    self.select{|str| str.ip_scan.count == 1}
  end

  def ip_find
    self.ip_select.first
  end
end

class String
  def ip_match
    self.ip_scan.first
  end

  def ip_scan
    self.scan(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}\b)/).select{|a| a.all?{|b| (0..255).include?(b.to_i)}}.map{|a| a.join('.')}
  end
end
