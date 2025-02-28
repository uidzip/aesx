#!/usr/local/bin/ruby

# Copyright (c) 2025 Tom Lahti
# MIT License

require 'minitest/autorun'
require 'aesx'
require 'digest'
require 'fileutils'
require 'securerandom'

class TestAESX < Minitest::Test
  def setup
    @key = SecureRandom.hex(32)
    @plaintext = "This is a test message!"
  end

  def test_key_normalization_with_hex_key
    hex_key = "a3dcb4b56faed1b20f43aee7e20b40513bf6c5f764c831b95372e142ebff4236"
    cipher = AESX::AESX.new(hex_key)
    normalized_key = cipher.instance_variable_get(:@key)
    assert_equal 32, normalized_key.bytesize, "The normalized key should be 32 bytes."
  end

  def test_key_normalization_with_short_hex_key
    short_hex_key = "a3dcb4b56faed1b20f43aee7e20b40"
    cipher = AESX::AESX.new(short_hex_key)
    normalized_key = cipher.instance_variable_get(:@key)
    assert_equal 32, normalized_key.bytesize, "The normalized key should be padded to 32 bytes."
  end

  def test_key_normalization_with_long_hex_key
    long_hex_key = "a3dcb4b56faed1b20f43aee7e20b40513bf6c5f764c831b95372e142ebff4236a3dcb4b56faed1b20f43aee7e20b4051"
    cipher = AESX::AESX.new(long_hex_key)
    normalized_key = cipher.instance_variable_get(:@key)
    assert_equal 32, normalized_key.bytesize, "The normalized key should be truncated to 32 bytes."
  end

  def test_key_normalization_with_non_hex_key
    password_key = "my password"
    cipher = AESX::AESX.new(password_key)
    normalized_key = cipher.instance_variable_get(:@key)
    assert_equal 32, normalized_key.bytesize, "The SHA-256 hashed key should be 32 bytes."
  end

  def test_encrypt_decrypt_with_base64_format
    encrypted = AESX.encrypt(@plaintext, @key, format: :base_64)
    decrypted = AESX.decrypt(encrypted, @key, format: :base_64)

    assert_equal @plaintext, decrypted, "Decrypted text should match the original plaintext."
  end

  def test_encrypt_decrypt_with_binary_format
    encrypted = AESX.encrypt(@plaintext, @key, format: :binary)
    decrypted = AESX.decrypt(encrypted, @key, format: :binary)

    assert_equal @plaintext, decrypted, "Decrypted text should match the original plaintext."
  end

  def test_encrypt_decrypt_with_plain_format
    encrypted = AESX.encrypt(@plaintext, @key, format: :plain)
    decrypted = AESX.decrypt(encrypted, @key, format: :plain)

    assert_equal @plaintext, decrypted, "Decrypted text should match the original plaintext."
  end

  def test_encrypt_decrypt_with_random_iv
    encrypted = AESX.encrypt(@plaintext, @key, format: :base_64)
    decrypted = AESX.decrypt(encrypted, @key, format: :base_64)

    assert_equal @plaintext, decrypted, "Decrypted text should match the original plaintext when using a random IV."
  end

  def test_encrypt_decrypt_with_32_byte_key
    key_32_bytes = "a" * 32  # exactly 32 bytes
    encrypted = AESX.encrypt(@plaintext, key_32_bytes, format: :base_64)
    decrypted = AESX.decrypt(encrypted, key_32_bytes, format: :base_64)

    assert_equal @plaintext, decrypted, "Decrypted text should match the original plaintext when using a 32-byte key."
  end

  def test_invalid_cipher_text
    # Generate a valid encrypted string first
    valid_encrypted = AESX.encrypt("test", @key, format: :base_64)
    # Corrupt the ciphertext portion
    parts = valid_encrypted.split('$')
    parts[1] = "invalidciphertext"
    invalid_encrypted = parts.join('$')

    assert_raises(OpenSSL::Cipher::CipherError) do
      AESX.decrypt(invalid_encrypted, @key, format: :base_64)
    end
  end

  def test_invalid_decryption_format
    invalid_encrypted = "invalidcipherdata"
    assert_raises(ArgumentError) do
      AESX.decrypt(invalid_encrypted, @key, format: :base_64)
    end
  end  

  def test_decrypt_with_invalid_key
    invalid_key = "invalidkey123456"  # Invalid key that won't match
    encrypted = AESX.encrypt(@plaintext, @key, format: :base_64)

    # Try to decrypt with an invalid key
    decrypted = nil
    assert_raises(OpenSSL::Cipher::CipherError) do
      decrypted = AESX.decrypt(encrypted, invalid_key, format: :base_64)
    end

    refute_equal @plaintext, decrypted, "Decryption with an invalid key should not yield the original plaintext."
  end

  def test_key_generation_default
    key = AESX.key
    assert_equal 32, key.bytesize, "Default key should be 32 bytes."
  end

  def test_key_generation_with_length
    key = AESX.key(128)
    assert_equal 16, key.bytesize, "128-bit key should be 16 bytes."
  end

  def test_key_generation_with_base64
    key = AESX.key(256, :base_64)
    decoded = Base64.decode64(key)
    assert_equal 32, decoded.bytesize, "Base64 key should decode to 32 bytes."
  end

  def test_iv_generation_default
    iv = AESX.iv
    assert_equal 12, iv.bytesize, "Default IV should be 12 bytes."
  end

  def test_iv_generation_with_base64
    iv = AESX.iv(:base_64)
    decoded = Base64.decode64(iv)
    assert_equal 12, decoded.bytesize, "Base64 IV should decode to 12 bytes."
  end

  def test_random_iv_and_key_methods
    aes = AESX::AESX.new("testkey" * 4)  # 32-byte key
    iv = aes.random_iv
    key = aes.random_key
    assert_equal 12, iv.bytesize, "Random IV should be 12 bytes."
    assert_equal 32, key.bytesize, "Random key should be 32 bytes."
  end

  def test_encrypt_decrypt_with_short_aes
    plaintext = "Secret message"
    cipher = 'AES-128-GCM'
    key = AESX.key(cipher: cipher)

    encrypted = AESX.encrypt(plaintext, key, cipher: cipher)
    decrypted = AESX.decrypt(encrypted, key, cipher: cipher)

    assert_equal plaintext, decrypted, "Decrypted text should match original with custom cipher."
  end

  def test_encrypt_decrypt_with_ctr
    plaintext = "Secret message"
    cipher = 'AES-256-CTR'
    key = AESX.key(cipher: cipher)

    encrypted = AESX.encrypt(plaintext, key, cipher: cipher)
    decrypted = AESX.decrypt(encrypted, key, cipher: cipher)

    assert_equal plaintext, decrypted, "Decrypted text should match original with custom cipher."
  end

  def test_encrypt_decrypt_with_aria
    plaintext = "Secret message"
    cipher = 'ARIA-256-CTR'
    key = AESX.key(cipher: cipher)

    encrypted = AESX.encrypt(plaintext, key, cipher: cipher)
    decrypted = AESX.decrypt(encrypted, key, cipher: cipher)

    assert_equal plaintext, decrypted, "Decrypted text should match original with custom cipher."
  end

  def test_encrypt_decrypt_with_sm4
    plaintext = "Secret message"
    cipher = 'SM4-CTR'
    key = AESX.key(cipher: cipher)

    encrypted = AESX.encrypt(plaintext, key, cipher: cipher)
    decrypted = AESX.decrypt(encrypted, key, cipher: cipher)

    assert_equal plaintext, decrypted, "Decrypted text should match original with custom cipher."
  end

  def test_encrypt_decrypt_with_chacha
    plaintext = "Secret message"
    cipher = 'chacha20-poly1305'
    key = AESX.key(cipher: cipher)

    encrypted = AESX.encrypt(plaintext, key, cipher: cipher)
    decrypted = AESX.decrypt(encrypted, key, cipher: cipher)

    assert_equal plaintext, decrypted, "Decrypted text should match original with custom cipher."
  end

  def test_disable_compression_with_all_formats
    # Create a larger string to better demonstrate compression
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Test with each format
    [:base_64, :binary, :plain].each do |format|
      encrypted = AESX.encrypt(large_plaintext, @key, format: format, compression: false)
      decrypted = AESX.decrypt(encrypted, @key)
      
      assert_equal large_plaintext, decrypted, "Decryption should match original plaintext with format #{format} and compression disabled"
    end
  end

  def test_zstd_compression_with_all_formats
    # Skip if zstd is not available
    skip "Zstd compression not available" unless AESCompression.algorithm_available?(:zstd)
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Test with each format
    [:base_64, :binary, :plain].each do |format|
      encrypted = AESX.encrypt(large_plaintext, @key, format: format, compression: :zstd)
      decrypted = AESX.decrypt(encrypted, @key)
      
      assert_equal large_plaintext, decrypted, "Decryption should match original plaintext with format #{format} and zstd compression"
    end
  end

  def test_snappy_compression_with_all_formats
    # Skip if snappy is not available
    skip "Snappy compression not available" unless AESCompression.algorithm_available?(:snappy)
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Test with each format
    [:base_64, :binary, :plain].each do |format|
      encrypted = AESX.encrypt(large_plaintext, @key, format: format, compression: :snappy)
      decrypted = AESX.decrypt(encrypted, @key)
      
      assert_equal large_plaintext, decrypted, "Decryption should match original plaintext with format #{format} and snappy compression"
    end
  end

  def test_lz4_compression_with_all_formats
    # Skip if lz4 is not available
    skip "LZ4 compression not available" unless AESCompression.algorithm_available?(:lz4)
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Test with each format
    [:base_64, :binary, :plain].each do |format|
      encrypted = AESX.encrypt(large_plaintext, @key, format: format, compression: :lz4)
      decrypted = AESX.decrypt(encrypted, @key)
      
      assert_equal large_plaintext, decrypted, "Decryption should match original plaintext with format #{format} and lz4 compression"
    end
  end

  def test_default_compression_with_all_formats
    # Skip if no compression algorithms are available
    skip "No compression algorithms available" unless AESCompression.default_algorithm
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Test with each format
    [:base_64, :binary, :plain].each do |format|
      # Using default compression (nil or not specified)
      encrypted = AESX.encrypt(large_plaintext, @key, format: format)
      decrypted = AESX.decrypt(encrypted, @key)
      
      assert_equal large_plaintext, decrypted, "Decryption should match original plaintext with format #{format} and default compression"
    end
  end

  def test_invalid_compression_algorithm
    assert_raises(ArgumentError) do
      AESX.encrypt("test", @key, compression: :invalid_algorithm)
    end
  end

  def test_cross_format_compatibility
    # Skip if no compression algorithms are available
    skip "No compression algorithms available" unless AESCompression.default_algorithm
    
    large_plaintext = "This is a test message with repetitive content. " * 50
    
    # Test encrypting with one format and decrypting with auto-detection
    encrypted_base64 = AESX.encrypt(large_plaintext, @key, format: :base_64)
    encrypted_binary = AESX.encrypt(large_plaintext, @key, format: :binary)
    encrypted_plain = AESX.encrypt(large_plaintext, @key, format: :plain)
    
    # Decrypt all without specifying format (should auto-detect)
    decrypted_from_base64 = AESX.decrypt(encrypted_base64, @key)
    decrypted_from_binary = AESX.decrypt(encrypted_binary, @key)
    decrypted_from_plain = AESX.decrypt(encrypted_plain, @key)
    
    assert_equal large_plaintext, decrypted_from_base64, "Should correctly decrypt base64 format with auto-detection"
    assert_equal large_plaintext, decrypted_from_binary, "Should correctly decrypt binary format with auto-detection"
    assert_equal large_plaintext, decrypted_from_plain, "Should correctly decrypt plain format with auto-detection"
  end

  def test_compression_algorithm_persistence
    # Skip if zstd is not available
    skip "Zstd compression not available" unless AESCompression.algorithm_available?(:zstd)
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Encrypt with a specific algorithm
    encrypted = AESX.encrypt(large_plaintext, @key, compression: :zstd)
    
    # Create a new instance with different default settings
    different_default = AESX::AESX.new(@key, compression: false)
    
    # It should still decrypt correctly by reading the embedded algorithm info
    decrypted = different_default.decrypt(encrypted)
    
    assert_equal large_plaintext, decrypted, "Should decrypt correctly even when instance defaults differ from encryption settings"
  end

  def test_cross_platform_compatibility
    # This test simulates what happens when data is encrypted on one system
    # and decrypted on another with different compression libraries available
    
    # Skip if no compression algorithms are available
    skip "No compression algorithms available" unless AESCompression.default_algorithm
    
    large_plaintext = "This is a test message with repetitive content. " * 100
    
    # Save the original state
    orig_algorithms = AESCompression.instance_variable_get(:@algorithms).dup
    orig_default = AESCompression.instance_variable_get(:@default_algorithm)
    
    begin
      # First, encrypt with zstd
      if AESCompression.algorithm_available?(:zstd)
        encrypted = AESX.encrypt(large_plaintext, @key, compression: :zstd)
        
        # Now simulate a system that only has snappy
        AESCompression.instance_variable_set(:@algorithms, 
          orig_algorithms.select { |k, _| k == :snappy })
        AESCompression.instance_variable_set(:@default_algorithm, :snappy)
        
        # It should still decrypt correctly by reading the embedded algorithm info
        # and using the correct decompression method or raising a clear error
        if AESCompression.algorithm_available?(:zstd)
          decrypted = AESX.decrypt(encrypted, @key)
          assert_equal large_plaintext, decrypted, "Should decompress with the correct algorithm"
        else
          assert_raises(RuntimeError) do
            AESX.decrypt(encrypted, @key)
          end
        end
      end
    ensure
      # Restore original state
      AESCompression.instance_variable_set(:@algorithms, orig_algorithms)
      AESCompression.instance_variable_set(:@default_algorithm, orig_default)
    end
  end

  def test_decrypt_with_unavailable_algorithm
    # Create encrypted data with a default algorithm
    large_plaintext = "This is a test message with repetitive content. " * 50
    encrypted = AESX.encrypt(large_plaintext, @key)
    
    # Save original state
    orig_algorithms = AESCompression.instance_variable_get(:@algorithms).dup
    
    begin
      # For base64 format, modify the compression flag
      parts = encrypted.split('$')
      
      # Determine an algorithm that isn't currently loaded
      # We'll use ID 3 for lz4 if it's not available, otherwise 2 for snappy
      algorithm_id = AESCompression.algorithm_available?(:lz4) ? 2 : 3
      
      # Ensure the algorithm we're testing isn't available
      AESCompression.instance_variable_set(:@algorithms, 
        orig_algorithms.reject { |k, _| k == AESCompression::ID_TO_ALGORITHM[algorithm_id] })
      
      # Set the compression flag to our chosen algorithm
      parts[3] = algorithm_id.to_s
      modified_encrypted = parts.join('$')
      
      # Try to decrypt with the modified compression flag
      assert_raises(RuntimeError) do
        AESX.decrypt(modified_encrypted, @key)
      end
    ensure
      # Restore original algorithms
      AESCompression.instance_variable_set(:@algorithms, orig_algorithms)
    end
  end
  
  def test_advanced_usage_non_default_cipher
    key = AESX.key(cipher: 'CHACHA20-POLY1305')
    
    # Create an AESX object with non-default cipher
    cipher = AESX::AESX.new(key, {
      cipher: 'CHACHA20-POLY1305',
      padding: true,
      compression: :zstd,
      auth_data: "additional authentication data"
    })

    # Test encryption
    message1 = "Message 1"
    message2 = "Message 2"
    
    encrypted1 = cipher.encrypt(message1)
    encrypted2 = cipher.encrypt(message2)
    
    # Verify successful encryption
    refute_nil encrypted1
    refute_nil encrypted2
    
    # Verify decryption
    decrypted1 = cipher.decrypt(encrypted1)
    decrypted2 = cipher.decrypt(encrypted2)
    
    assert_equal message1, decrypted1
    assert_equal message2, decrypted2
  end

end
