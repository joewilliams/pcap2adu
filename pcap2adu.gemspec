lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pcap2adu/version'
require 'rake'

spec = Gem::Specification.new do |s|
  s.name = "pcap2adu"
  s.version = Pcap2adu::VERSION
  s.author = "joe williams"
  s.email = "joe@joetify.com"
  s.homepage = "http://github.com/joewilliams/pcap2adu"
  s.platform = Gem::Platform::RUBY
  s.summary = "a tcp thing"
  s.files = FileList["{bin,lib}/**/*"].to_a
  s.require_path = "lib"
  s.bindir = "bin"
  s.executables = %w( pcap2adu )
  s.has_rdoc = true
  s.extra_rdoc_files = ["README.md"]
  %w{packetfu docopt sqlite3 ffi-pcap ffi-packets}.each { |gem| s.add_dependency gem }
  s.add_development_dependency "bundler", "~> 1.5"
  s.add_development_dependency "rake"
end
