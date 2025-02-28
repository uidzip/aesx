# AESX

A lightweight encryption library that provides an extended version of the popular AES gem interface with modern ciphers. The default cipher is AES-256-GCM. Other than the output formats being slightly extended to accommodate GCM authentication tags and compression indicators, this is a drop-in replacement for the AES gem. The API of that gem is fully implemented.  AESX adds a binary format which is more efficiently stored than base64, and compression.

Security-wise, GCM ciphers provide tampering prevention and data integrity automatically. When using AESX, a regular password-style key of any length can be provided and a cryptographically secure encryption key will be generated using a key derivation function.
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
# Check what compression algorithms are available (what gems loaded)
AESX.available_compression  # => [:zstd, :snappy, :lz4]

# Check the default compression algorithm
AESX.default_compression    # => :zstd
```

Available compression algorithms:
- `:zstd` - High compression ratio with good speed (default if available)
- `:snappy` - Fast compression with moderate ratio
- `:lz4` - Very fast compression with lower ratio

AESX attempts to load zstd, then snappy, then lz4.  The first one that loads successfully is the default.  If none of them load, compression is disabled.  Install gems to have compression available:

| **Compression** | **Ruby** gem | **JRuby** gem  |
|:---------------:|:------------:|:--------------:|
| :zstd           | zstd-ruby    | zstandard-ruby |
| :snappy         | snappy       | jruby-snappy   |
| :lz4            | lz4-ruby     | jruby-lz4      |
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

You don’t have to supply the cipher with every operation. You can instead create an object configured for a particular cipher, and then reuse that object for multiple operations.

```ruby
# Create an AESX object for multiple operations
cipher = AESX::AESX.new(key, {
  cipher: 'AES-192-GCM',
  padding: true,
  compression: :snappy,
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

The compression information is stored as part of the encrypted data, so files encrypted on one system can be decrypted on another, even if different compression libraries are available. If the required compression algorithm is not available during decryption, a clear error message will be displayed. Compression can also be completely disabled.

## Notes on Security

- GCM and CHACHA20-POLY1305 provide authenticated encryption, meaning they detect tampering with the encrypted data
- When using CTR mode, no authentication is provided
- You can use AESX to provide a secure random key (generated with `AESX.key`)
- **CRITICAL SECURITY WARNING**: Never store the encryption key with the encrypted data
  - Storing key and encrypted data together compromises all encryption
  - Manage keys separately using secure key management practices
- When providing your own key via a password, key derivation uses PBKDF2 with a deterministic salt derived from the input
  - Ensures consistent key stretching across systems
  - Requires OpenSSL >= 1.0.0
  - The same input/password will always produce the same derived key

## License

This library is available as open source under the terms of the MIT License.