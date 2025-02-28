Gem::Specification.new do |spec|
  spec.name          = "aesx"
  spec.version       = "0.1.0"
  spec.authors       = ["Tom lahti"]
  spec.email         = ["uidzip@gmail.com"]
  spec.summary       = "A lightweight encryption library, in the style of the AES gem"
  spec.description   = "Provides almost the same interface as the AES gem, but with modern ciphers. The default cipher is AES-256-GCM. For a list of supported ciphers, run AESX.cipher_list"
  spec.license       = "MIT"

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
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
end
