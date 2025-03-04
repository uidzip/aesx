Gem::Specification.new do |spec|
  spec.name          = "aesx"
  spec.version       = "0.1.4"
  spec.authors       = ["Tom lahti"]
  spec.email         = ["uidzip@gmail.com"]
  spec.summary       = "AES gem, but with GCM/CTR ciphers, compression, and more"
  spec.description   = "Provides almost the same interface as the AES gem, but with modern ciphers and compression. The default cipher is AES-256-GCM. See the README for details."
  spec.license       = "MIT"
  spec.homepage      = 'https://rubygems.org/gems/aesx'

  spec.files         = Dir["lib/**/*.rb", "test_aesx.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 3.0"
  spec.add_dependency "openssl", ">= 2.0"
  
  # Platform-specific compression dependencies
  if RUBY_PLATFORM =~ /java/
    spec.add_development_dependency "zstandard-ruby" # Optional zstd for JRuby
    spec.add_development_dependency "jruby-snappy"  # Optional snappy for JRuby
    spec.add_development_dependency "jruby-lz4"     # Optional lz4 for JRuby
  else
    spec.add_development_dependency "zstd-ruby"    # Optional zstd for MRI
    spec.add_development_dependency "snappy"       # Optional snappy for MRI
    spec.add_development_dependency "lz4-ruby"     # Optional lz4 for MRI
  end
    
  spec.homepage = "https://github.com/uidzip/aesx"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["documentation_uri"] = "https://www.rubydoc.info/gems/aesx"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
end
