# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pcap_simple/version'

Gem::Specification.new do |spec|
  spec.name          = 'pcap_simple'
  spec.version       = PcapSimple::VERSION
  spec.authors       = ['Ryan Breed']
  spec.email         = ["opensource@breed.org"]

  spec.summary       = %q{ A pure ruby pcap file reader }
  spec.description   = %q{ Not guaranteed to actually be correct }
  spec.homepage      = 'https://github.com/ryanbreed/pcap_simple'
  spec.license       = 'MIT'

  spec.metadata['allowed_push_host'] = 'https://in.breed.org'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'bit-struct'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'pry-doc'
  spec.add_development_dependency 'bundler', '~> 1.14'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
