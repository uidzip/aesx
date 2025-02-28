# AESX

A lightweight encryption library that provides an extended version of the popular AES gem interface with modern ciphers. The default cipher is AES-256-GCM.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'aesx'
```

And then execute:

```
$ bundle install
```

Or install it yourself:

```
$ gem install aesx
```

## Usage

### Basic Encryption and Decryption

```ruby
require 'aesx'

# Encrypt with a key
key = AESX.key
encrypted = AESX.encrypt("Secret message", key)

# Decrypt
decrypted = AESX.decrypt(encrypted, key)
```

### Using Different Ciphers

```ruby
# List available ciphers
puts AESX.cipher_list

# Use a specific cipher
key = AESX.key(cipher: 'CHACHA20-POLY1305')
encrypted = AESX.encrypt("Secret message", key, cipher: 'CHACHA20-POLY1305')
decrypted = AESX.decrypt(encrypted, key, cipher: 'CHACHA20-POLY1305')
```

### Compression

The library supports compression to reduce the size of encrypted data. By default, compression is enabled using the best available algorithm.

```ruby
# Compression is enabled by default
encrypted = AESX.encrypt("Large content to encrypt", key)

# Disable compression
encrypted = AESX.encrypt("Data to encrypt", key, compression: false)

# Specify a compression algorithm
encrypted = AESX.encrypt("Large content to encrypt", key, compression: :zstd)
encrypted = AESX.encrypt("Large content to encrypt", key, compression: :snappy)
encrypted = AESX.encrypt("Large content to encrypt", key, compression: :lz4)
```

#### Compression Information

```ruby
# Check what compression algorithms are available
AESX.available_compression  # => [:zstd, :snappy, :lz4]

# Check the default compression algorithm
AESX.default_compression    # => :zstd
```

Available compression algorithms:
- `:zstd` - High compression ratio with good speed (default if available)
- `:snappy` - Fast compression with moderate ratio
- `:lz4` - Very fast compression with lower ratio

Note: You'll need to install the corresponding gem for each algorithm:
- For zstd: `gem install zstd-ruby` (or `zstandard-ruby` for JRuby)
- For snappy: `gem install snappy` (or `jruby-snappy` for JRuby)
- For lz4: `gem install lz4-ruby` (or `jruby-lz4` for JRuby)

### Output Formats

AESX supports multiple output formats:

```ruby
# Base64 encoded string (default)
encrypted = AESX.encrypt("Secret message", key, format: :base_64)

# Raw binary output
encrypted = AESX.encrypt("Secret message", key, format: :binary)

# Array of components [iv, ciphertext, auth_tag, compression_algorithm]
encrypted = AESX.encrypt("Secret message", key, format: :plain)
```

### Advanced Usage

```ruby
# Create an AESX object for multiple operations
cipher = AESX::AESX.new(key, {
  cipher: 'AES-256-GCM',
  padding: true,
  compression: :zstd,
  auth_data: "additional authentication data" # for GCM mode
})

encrypted1 = cipher.encrypt("Message 1")
encrypted2 = cipher.encrypt("Message 2")
```

## Supported Ciphers

- AES-128/192/256-GCM
- AES-128/192/256-CTR
- ARIA-128/192/256-CTR[^1]
- SM4-CTR[^2]
- SM4-GCM[^2]
- CHACHA20-POLY1305

The actual list depends on your OpenSSL version. Use `AESX.cipher_list` to see available ciphers.

[^1]: ARIA is a block cipher developed by South Korean cryptographers and is widely used in South Korea, particularly in government and financial systems.

[^2]: SM4 is the Chinese national standard block cipher algorithm and is commonly used within China in government and regulated industries.

## Cross-Platform Compatibility

The compression information is stored as part of the encrypted data, so files encrypted on one system can be decrypted on another, even if different compression libraries are available. If the required compression algorithm is not available during decryption, a clear error message will be displayed.

## Notes on Security

- GCM and CHACHA20-POLY1305 provide authenticated encryption
- When using CTR mode, no authentication is provided
- Always use a secure random key (generated with `AESX.key`)
- **CRITICAL SECURITY WARNING**: Never store the encryption key with the encrypted data
  - Storing key and encrypted data together compromises all encryption
  - Manage keys separately using secure key management practices
- Key derivation uses PBKDF2 with a deterministic salt derived from the input key
  - Ensures consistent key stretching across systems
  - Requires OpenSSL >= 1.0.0
  - The same input key will always produce the same derived key

## License

This library is available as open source under the terms of the MIT License.
