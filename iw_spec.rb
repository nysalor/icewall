require File.dirname(__FILE__) + '/icewall'

describe Icewall, "ファイル名が渡されなかった場合" do
  before(:each) do
    @icewall = Icewall.new
  end

  it "blacklistは空になる" do
    @icewall.blacklist.should == []
  end
  it "whitelistlistは空になる" do
    @icewall.whitelist.should == []
  end
end

describe Icewall, "ファイル名を渡した場合" do
  before(:each) do
    @icewall = Icewall.new(:blacklist => 'fixtures/deny.list', :whitelist => 'fixtures/allow.list')
    @blacklist_count = File.read('fixtures/deny.list').split("\n").count
    @whitelist_count = File.read('fixtures/allow.list').split("\n").count
  end

  it "blacklistは2つ" do
    @icewall.blacklist.count.should == @blacklist_count
  end
  it "whitelistlistは2つ" do
    @icewall.whitelist.count.should == @whitelist_count
  end
end

describe Icewall, "ブラックリストに追加した場合" do
  before(:each) do
    @icewall = Icewall.new(:blacklist => 'fixtures/deny.list', :whitelist => 'fixtures/allow.list')
  end

  it "blacklistが１つ増えること" do
    lambda {
      @icewall.deny("0.0.0.1")
    }.should change{ @icewall.blacklist.count }.by(1)
  end

  it "ソートすると先頭が0.0.0.1になっていること" do
    @icewall.deny("0.0.0.1")
    @icewall.sort!
    @icewall.blacklist.first.should == "0.0.0.1"
  end

  it "重複するアドレスを加えても要素数が変化しないこと" do
    @icewall.deny("101.102.103.1")
    lambda {
      @icewall.deny("101.102.103.1")
    }.should_not change{ @icewall.blacklist.count }
  end

  it "ホワイトリストに入っているアドレスを加えても要素数が変化しないこと" do
    lambda {
      @icewall.allow("10.10.10.11")
      @icewall.deny("10.10.10.11")
    }.should_not change{ @icewall.blacklist.count }
  end

  it "正しいアドレスを判別できること" do
    ["0.0.0.1"].ip_select.first.should == "0.0.0.1"
  end

  it "正しくないアドレスを判別できること" do
    ["eee.134.d.11"].ip_select.should == []
  end

  it "正しくないアドレスを加えても要素数が変化しないこと" do
    lambda {
      @icewall.deny("320.257.1.23")
    }.should_not change{ @icewall.blacklist.count }
  end

end

describe Icewall, "ホワイトリストに追加した場合" do
    before(:each) do
    @icewall = Icewall.new(:blacklist => 'fixtures/deny.list', :whitelist => 'fixtures/allow.list')
  end

  it "whitelistが１つ増えること" do
    lambda {
      @icewall.allow("0.0.0.1")
    }.should change{ @icewall.whitelist.count }.by(1)
  end

  it "ソートすると先頭が0.0.0.1になっていること" do
    @icewall.allow("0.0.0.1")
    @icewall.sort!
    @icewall.whitelist.first.should == "0.0.0.1"
  end
end

describe Array, "配列にIPアドレスが含まれている場合" do
    before(:each) do
    @addresses = ["1.1.1.1","2.2.2.2","hello!"]
  end

  it "IPアドレスの要素だけを抜き出せること" do
    @addresses.ip_select.should == ["1.1.1.1","2.2.2.2"]
  end
end

describe Array, "配列に複数のIPアドレスを含む要素がある場合" do
    before(:each) do
    @addresses = ["1.1.1.1","2.2.2.2","3.3.3.3 4.4.4.4 5.5.5.5"]
  end

  it "複数のIPアドレスを含む要素は捨てること" do
    @addresses.ip_select.should == ["1.1.1.1","2.2.2.2"]
  end
end
