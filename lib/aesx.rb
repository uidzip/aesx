# Copyright (c) 2025 Tom Lahti
# MIT License

require 'openssl'
require 'base64'
require 'digest'
require_relative 'compression'

# AESX - AES eXtended encryption library
#
# A lightweight encryption library that provides an extended version of 
# the popular AES gem interface with modern ciphers. The default cipher 
# is AES-256-GCM.
#
# @example Basic usage
#   key = AESX.key
#   encrypted = AESX.encrypt("Secret message", key)
#   decrypted = AESX.decrypt(encrypted, key)
#
# @example Using different ciphers
#   key = AESX.key(cipher: 'CHACHA20-POLY1305')
#   encrypted = AESX.encrypt("Secret message", key, cipher: 'CHACHA20-POLY1305')
#
# @example With compression
#   encrypted = AESX.encrypt("Large message", key, compression: :zstd)
#
module AESX

  # Mapping of cipher names to [key_length, iv_length]
  CIPHER_SPECS = {
    'AES-128-CTR'    => [16, 16],
    'AES-192-CTR'    => [24, 16],
    'AES-256-CTR'    => [32, 16],
    'AES-128-GCM'    => [16, 12],
    'AES-192-GCM'    => [24, 12],
    'AES-256-GCM'    => [32, 12],
    'ARIA-128-CTR'   => [16, 16],
    'ARIA-192-CTR'   => [24, 16],
    'ARIA-256-CTR'   => [32, 16],
    'SM4-CTR'        => [16, 16],
    'SM4-GCM'        => [16, 12],
    'CHACHA20-POLY1305' => [32, 12]
  }.freeze

  class << self

    # Returns a list of supported ciphers available in the current OpenSSL installation
    #
    # @return [Array<String>] List of available cipher names
    def cipher_list
      openssl_ciphers = OpenSSL::Cipher.ciphers.map(&:upcase)
      CIPHER_SPECS.keys & openssl_ciphers    
    end

    # Encrypts plaintext using the specified key and options
    #
    # @param plaintext [String] The data to encrypt
    # @param key [String] The encryption key
    # @param opts [Hash] Options for encryption
    # @option opts [Symbol] :format (:base_64) Output format - :base_64, :binary, or :plain
    # @option opts [String] :cipher ('AES-256-GCM') Cipher to use
    # @option opts [String] :iv (random) Initialization vector
    # @option opts [Boolean, Integer] :padding (true) Enable padding
    # @option opts [String] :auth_data ('') Additional authentication data for GCM mode
    # @option opts [Boolean, Symbol] :compression (default algorithm) Compression option
    #
    # @return [String, Array] Encrypted data in the specified format
    def encrypt(plaintext, key, opts={})
      cipher = AESX.new(key, opts)
      cipher.encrypt(plaintext)
    end

    # Decrypts ciphertext using the specified key and options
    #
    # @param ciphertext [String, Array] The encrypted data to decrypt
    # @param key [String] The encryption key
    # @param opts [Hash] Options for decryption (most are auto-detected)
    # @option opts [Symbol] :format (auto-detected) Input format
    # @option opts [String] :cipher ('AES-256-GCM') Cipher to use
    # @option opts [Boolean, Integer] :padding (true) Enable padding
    # @option opts [String] :auth_data ('') Additional authentication data for GCM mode
    #
    # @return [String] The decrypted plaintext
    # @raise [OpenSSL::Cipher::CipherError] If decryption fails (wrong key, tampered data)
    def decrypt(ciphertext, key, opts={})
      cipher = AESX.new(key, opts)
      cipher.decrypt(ciphertext)
    end

    # Generates a random key of appropriate length for the specified cipher
    #
    # @param length [Integer, nil] Key length in bits, or nil to use cipher default
    # @param format [Symbol] Output format - :plain or :base_64
    # @param cipher [String] Cipher to determine key length
    #
    # @return [String] A random key in the specified format
    def key(length = nil, format = :plain, cipher: 'AES-256-GCM')
      key_length = length ? length / 8 : CIPHER_SPECS[cipher.upcase][0]
      key = OpenSSL::Random.random_bytes(key_length)
      format == :base_64 ? Base64.encode64(key).chomp : key
    end

    # Generates a random initialization vector of appropriate length for the specified cipher
    #
    # @param format [Symbol] Output format - :plain or :base_64
    # @param cipher [String] Cipher to determine IV length
    #
    # @return [String] A random IV in the specified format
    def iv(format = :plain, cipher: 'AES-256-GCM')
      iv_length = CIPHER_SPECS[cipher.upcase][1]
      iv = OpenSSL::Random.random_bytes(iv_length)
      format == :base_64 ? Base64.encode64(iv).chomp : iv
    end
    
    # Returns the default compression algorithm
    #
    # @return [Symbol, nil] The symbol representing the default algorithm, or nil if none available
    def default_compression
      AESCompression.default_algorithm
    end
    
    # Returns an array of available compression algorithms
    #
    # @return [Array<Symbol>] Symbols representing available compression algorithms
    def available_compression
      AESCompression.available_algorithms
    end

  end

  # Main AESX class for encryption and decryption operations
  class AESX
    attr :key, :iv, :cipher, :auth_tag, :options

    # Creates a new AESX cipher instance
    #
    # @param key [String] The encryption key
    # @param opts [Hash] Options for the cipher
    # @option opts [Symbol] :format (:base_64) Default output format
    # @option opts [String] :cipher ('AES-256-GCM') Cipher to use
    # @option opts [String] :iv (random) Initialization vector
    # @option opts [Boolean, Integer] :padding (true) Enable padding
    # @option opts [String] :auth_data ('') Additional authentication data for GCM mode
    # @option opts [Boolean, Symbol] :compression (default algorithm) Compression option
    #
    # @raise [ArgumentError] If an unsupported cipher is specified
    def initialize(key, opts={})
      # allow laziness
      if opts.key?(:compress)
        opts[:compression] = opts.delete(:compress)
      end      
      @options = {
        format: :base_64,        # Default output format for encryption
        cipher: "AES-256-GCM",   # GCM mode
        iv: nil,                 # IV will be generated if not passed
        padding: true,           # OpenSSL padding support
        auth_data: "",           # additional authenication data (AAD)
        compression: AESCompression.default_algorithm # Default to the default algorithm
      }.merge!(opts)

      unless ::AESX.cipher_list.include?(@options[:cipher].upcase)
        raise ArgumentError, "Unsupported cipher #{@options[:cipher]}. Supported ciphers: #{::AESX.cipher_list.join(', ')}"
      end

      @key = normalize_key(key, @options[:cipher])
      @iv = @options[:iv] || ::AESX.iv(cipher: @options[:cipher])

      case @options[:padding]
      when true
        @options[:padding] = 1
      when false
        @options[:padding] = 0
      end

      @cipher = OpenSSL::Cipher.new(@options[:cipher])
    end

    # Encrypts plaintext using the configured cipher and options
    #
    # @param plaintext [String] The data to encrypt
    # @param opts [Hash] Options to override instance defaults
    # @option opts [Symbol] :format Output format override
    # @option opts [String] :iv Override the instance IV
    # @option opts [Boolean, Symbol] :compression Compression override
    #
    # @return [String, Array] Encrypted data in the specified format
    def encrypt(plaintext, opts = {})
      @cipher.encrypt
      @cipher.key = @key
      iv = opts[:iv] || @iv
      @cipher.iv = iv
      @cipher.padding = @options[:padding]
      @cipher.auth_data = @options[:auth_data] unless @options[:cipher] =~ /CTR/i

      # Apply compression if enabled
      compressed_data = plaintext
      compression_algorithm = nil

      # Get compression option from opts or fallback to options
      compression = opts.key?(:compression) ? opts[:compression] : @options[:compression]
      
      # If compression is a symbol or truthy value (but not true), use it as the algorithm
      if compression.is_a?(Symbol) || (compression && compression != true)
        # Check if specified algorithm is available
        if compression.is_a?(Symbol) && !AESCompression.algorithm_available?(compression)
          raise ArgumentError, "Compression algorithm '#{compression}' is not available. Installed algorithms: #{AESCompression.available_algorithms.join(', ')}"
        end
        compressed_data, compression_algorithm = AESCompression.compress(plaintext, compression)
      # If compression is true or nil, use default algorithm
      elsif compression.nil? || compression == true
        compressed_data, compression_algorithm = AESCompression.compress(plaintext, AESCompression.default_algorithm)
      # Otherwise, no compression (compression == false)
      end

      ciphertext = @cipher.update(compressed_data) + @cipher.final
      auth_tag = @cipher.auth_tag unless @options[:cipher] =~ /CTR/i

      fmt = opts[:format] || @options[:format]
      case fmt
      when :base_64
        iv_b64 = Base64.encode64(iv).chomp
        ciphertext_b64 = Base64.encode64(ciphertext).chomp
        auth_tag_b64 = auth_tag ? Base64.encode64(auth_tag).chomp : nil
        
        # Add compression flag
        comp_flag = compression_algorithm ? AESCompression::ALGORITHM_IDS[compression_algorithm].to_s : "0"
        
        if auth_tag_b64
          result = "#{iv_b64}$#{ciphertext_b64}$#{auth_tag_b64}$#{comp_flag}"
        else
          result = "#{iv_b64}$#{ciphertext_b64}$$#{comp_flag}"  # Empty auth_tag field for CTR mode
        end
        result.force_encoding(Encoding::US_ASCII)
      when :binary
        # IV length has a range of 7-16, which we can get into 3 bits
        # auth_tag length is 0-16, variable in CCM
        auth_tag_size = auth_tag ? auth_tag.bytesize : 0
        packed_lengths = ((iv.bytesize - 7) << 5) | (auth_tag_size & 0x1F)
        
        # Add a second byte for compression algorithm
        compression_byte = AESCompression::ALGORITHM_IDS[compression_algorithm] || 0
        
        if auth_tag
          pack_format = "CC a#{iv.bytesize} a* a#{auth_tag.bytesize}"
          [packed_lengths, compression_byte, iv, ciphertext, auth_tag].pack(pack_format)
        else
          pack_format = "CC a#{iv.bytesize} a*"
          [packed_lengths, compression_byte, iv, ciphertext].pack(pack_format)
        end
      else
        [iv, ciphertext, auth_tag, compression_algorithm]
      end
    end

    # Decrypts ciphertext using the configured cipher and options
    #
    # @param encrypted_data [String, Array] The encrypted data to decrypt
    # @param opts [Hash] Options to override instance defaults
    # @option opts [Symbol] :format Format override (auto-detected if not specified)
    # @option opts [Boolean, Integer] :padding Padding override
    # @option opts [String] :auth_data Authentication data override for GCM mode
    #
    # @return [String] The decrypted plaintext
    # @raise [OpenSSL::Cipher::CipherError] If decryption fails
    # @raise [RuntimeError] If decompression fails or algorithm is unavailable
    def decrypt(encrypted_data, opts = {})
      # ignore provided opts[:format] and auto-detect
      compression_algorithm = nil

      case encrypted_data
      when Array
        opts[:format] = :plain
        iv, ciphertext, auth_tag, compression_algorithm = encrypted_data
      else
        opts[:format] = :binary

        # unless it's Base64 encoded?
        parts = encrypted_data.split('$')
        if parts.size.between?(3, 4)
          all_base64 = parts.all? { |str| str.nil? || str.empty? || str =~ /^[A-Za-z0-9+\/=]*$/ }
          if all_base64
            opts[:format] = :base_64
          end
        end
      end

      case opts[:format]
      when :base_64
        parts = encrypted_data.split('$')
        iv_b64 = parts[0]
        ciphertext_b64 = parts[1]
        auth_tag_b64 = parts[2] if parts.size >= 3 && !parts[2].nil? && !parts[2].empty?
        compression_code = parts[3] if parts.size >= 4
        
        iv = Base64.decode64(iv_b64)
        ciphertext = Base64.decode64(ciphertext_b64)
        auth_tag = auth_tag_b64 ? Base64.decode64(auth_tag_b64) : nil
        
        # Determine compression algorithm from the code
        if compression_code && compression_code != "0"
          algorithm_id = compression_code.to_i
          compression_algorithm = AESCompression::ID_TO_ALGORITHM[algorithm_id]
        end
      when :binary
        # Extract the first byte which contains IV and auth tag lengths
        lengths = encrypted_data.unpack1('C')
        
        # Extract the second byte which contains compression info
        compression_byte = encrypted_data.unpack('CC')[1]
        
        # Calculate IV length and auth tag length
        iv_len = ((lengths >> 5) & 0x07) + 7
        tag_len = lengths & 0x1F
        
        # Extract IV, ciphertext, and auth tag
        iv = encrypted_data[2, iv_len] # 2 bytes of header now
        
        if tag_len > 0
          auth_tag = encrypted_data[-tag_len, tag_len]
          # Ciphertext starts after header and IV, ends before auth tag
          ciphertext = encrypted_data[(2 + iv_len)...-tag_len]
        else
          auth_tag = nil
          ciphertext = encrypted_data[(2 + iv_len)..]
        end
        
        # Get compression algorithm
        compression_algorithm = AESCompression::ID_TO_ALGORITHM[compression_byte] if compression_byte != 0
      else
        iv, ciphertext, auth_tag, compression_algorithm = encrypted_data
      end

      @cipher.decrypt
      @cipher.key = @key
      @cipher.iv = iv
      unless @options[:cipher] =~ /CTR/i
        @cipher.auth_tag = auth_tag if auth_tag
        @cipher.auth_data = opts[:auth_data] || @options[:auth_data]
      end
      @cipher.padding = opts[:padding] || @options[:padding]

      decrypted_data = @cipher.update(ciphertext) + @cipher.final
      
      # Apply decompression if data was compressed
      if compression_algorithm
        begin
          decrypted_data = AESCompression.decompress(decrypted_data, compression_algorithm)
        rescue => e
          raise "Error decompressing data: #{e.message}. Algorithm #{compression_algorithm} may not be installed."
        end
      end

      decrypted_data
    end

    alias_method :random_iv, :iv
    alias_method :random_key, :key

    # Normalizes an encryption key to the correct length and format
    #
    # Requires OpenSSL >= 1.0.0 for PBKDF2 key derivation support.
    #
    # If the key is already the correct length, it's returned as-is.
    # If it's a hex string, it's converted to binary.
    # For other keys, PBKDF2 is used for deterministic key derivation
    #
    # @param key [String] The encryption key to normalize
    # @param cipher [String] Cipher to determine required key length (default: 'AES-256-GCM')
    # @param iterations [Integer] Number of iterations for PBKDF2 key derivation (default: 10000)
    #
    # @return [String] Normalized key of the correct length for the cipher
    # @raise [RuntimeError] If OpenSSL version is less than 1.0.0
    # @api private
    def normalize_key(key, cipher = 'AES-256-GCM', iterations: 10000)
      key_length = CIPHER_SPECS[cipher.upcase][0]
      return key if key.bytesize == key_length
            
      if key.match?(/\A[0-9a-fA-F]+\z/) # is it a hex string?
        key = key.unpack('a2' * key_length).map { |x| x.hex }.pack('c' * key_length)
      else
        # Derive salt deterministically from the key
        salt = Digest::SHA256.digest(key)[0,16]
        # Use PBKDF2 for key derivation
        key = OpenSSL::PKCS5.pbkdf2_hmac(key,salt,iterations,key_length,OpenSSL::Digest::SHA256.new)
      end
      
      key
    end

  end
end