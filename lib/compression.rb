# Copyright (c) 2025 Tom Lahti
# MIT License

module AESCompression
  @algorithms = {}
  @default_algorithm = nil

  # Compression algorithm identifiers for serialization
  ALGORITHM_IDS = {
    nil => 0,      # No compression
    :zstd => 1,
    :snappy => 2,
    :lz4 => 3
  }.freeze

  ID_TO_ALGORITHM = ALGORITHM_IDS.invert.freeze

  # Try to load zstd with platform-specific support
  begin
    if defined?(JRUBY_VERSION)
      require 'zstandard-ruby'
      @algorithms[:zstd] = {
        compress: ->(data) { Zstandard.compress(data) },
        decompress: ->(data) { Zstandard.decompress(data) }
      }
      @default_algorithm = :zstd
    else
      require 'zstd-ruby'
      @algorithms[:zstd] = {
        compress: ->(data) { Zstd.compress(data) },
        decompress: ->(data) { Zstd.decompress(data) }
      }
      @default_algorithm = :zstd
    end
  rescue LoadError
    # zstd not available
  end

  # Try to load snappy with platform-specific support
  begin
    if defined?(JRUBY_VERSION)
      require 'jruby-snappy'
      @algorithms[:snappy] = {
        compress: ->(data) { Snappy.deflate(data) },
        decompress: ->(data) { Snappy.inflate(data) }
      }
    else
      require 'snappy'
      @algorithms[:snappy] = {
        compress: ->(data) { Snappy.deflate(data) },
        decompress: ->(data) { Snappy.inflate(data) }
      }
    end
    @default_algorithm ||= :snappy
  rescue LoadError
    # snappy not available
  end

  # Try to load lz4 with platform-specific support
  begin
    if defined?(JRUBY_VERSION)
      require 'jruby-lz4'
      @algorithms[:lz4] = {
        compress: ->(data) { LZ4::compress(data) },
        decompress: ->(data) { LZ4::uncompress(data, data.bytesize * 3) } # Estimate output size
      }
    else
      require 'lz4-ruby'
      @algorithms[:lz4] = {
        compress: ->(data) { LZ4.compress(data) },
        decompress: ->(data) { LZ4.decompress(data) }
      }
    end
    @default_algorithm ||= :lz4
  rescue LoadError
    # lz4 not available
  end

  def self.available_algorithms
    @algorithms.keys
  end

  def self.algorithm_available?(algorithm)
    @algorithms.key?(algorithm)
  end

  def self.default_algorithm
    @default_algorithm
  end

  def self.compress(data, algorithm = nil)
    return [data, nil] unless data && !data.empty?

    algorithm ||= @default_algorithm
    return [data, nil] unless algorithm && @algorithms[algorithm]

    begin
      compressed = @algorithms[algorithm][:compress].call(data)
      [compressed, algorithm]
    rescue => e
      # Fallback to uncompressed data on error
      [data, nil]
    end
  end

  def self.decompress(data, algorithm)
    return data unless data && !data.empty? && algorithm
    
    # Check if algorithm is a valid symbol we recognize
    unless ID_TO_ALGORITHM.values.include?(algorithm)
      raise "Unknown compression algorithm identifier: #{algorithm}"
    end
    
    # Check if the algorithm is available
    unless @algorithms[algorithm]
      raise "Compression algorithm #{algorithm} required but not available. Please install the required gem."
    end

    begin
      @algorithms[algorithm][:decompress].call(data)
    rescue => e
      raise "Error decompressing data: #{e.message}. The #{algorithm} library may not be installed correctly."
    end
  end

  def self.enabled?
    !@algorithms.empty?
  end
end
