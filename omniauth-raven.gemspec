# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/raven/version'

Gem::Specification.new do |gem|

  gem.add_runtime_dependency 'omniauth', '~> 1.0'


  gem.name          = "omniauth-raven"
  gem.version       = Omniauth::Raven::VERSION
  gem.authors       = ["Lucian Carata"]
  gem.email         = ["lc525@cam.ac.uk"]
  gem.description   = "Omniauth provider for Raven"
  gem.summary       = "Implements an Omniauth provider for Raven, the central web authentication service at the University of Cambridge"
  gem.homepage      = "https://github.com/lc525/omniauth-raven"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
end
