<?php
/**
 * Main
 *
 * @package VideoPressUploader
 **/

namespace VideoPressUploader;

use InvalidArgumentException;

// Avoid direct calls to this file.
if ( ! defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Class Tus_File.
 *
 * @package VideoPressUploader
 */
class Tus_File {
	const CHUNK_SIZE    = 8192; // 8 kilobytes.
	const INPUT_STREAM  = 'php://input';
	const READ_BINARY   = 'rb';
	const APPEND_BINARY = 'ab';

	/**
	 * The input stream.
	 *
	 * @var string
	 */
	protected static $input_stream = self::INPUT_STREAM;

	/**
	 * The key.
	 *
	 * @var string The key.
	 */
	protected $key;

	/**
	 * The file checksum.
	 *
	 * @var string
	 */
	protected $checksum;

	/**
	 * The file name.
	 *
	 * @var string
	 */
	protected $name;

	/**
	 * The cache we are using.
	 *
	 * @var Tus_Abstract_Cache
	 */
	protected $cache;

	/**
	 * The current file offset.
	 *
	 * @var int
	 */
	protected $offset;

	/**
	 * The location.
	 *
	 * @var string
	 */
	protected $location;

	/**
	 * The file path.
	 *
	 * @var string
	 */
	protected $file_path;

	/**
	 * The file size.
	 *
	 * @var int
	 */
	protected $file_size;

	/**
	 * The upload metadata.
	 *
	 * @var array
	 */
	private $upload_metadata = array();

	/**
	 * File constructor.
	 *
	 * @param string|null             $name Name.
	 * @param Tus_Abstract_Cache|null $cache Cache.
	 */
	public function __construct( $name = null, $cache = null ) {
		$this->name  = $name;
		$this->cache = $cache;
	}

	/**
	 * Returns an integer if it's castable. Otherwise it throws
	 *
	 * @param string|int $number Number to cast.
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return int
	 */
	public function ensure_integer( $number ) {
		if ( ! is_numeric( $number ) ) {
			throw new InvalidArgumentException( 'argument needs to be an integer. Check stacktrace' );
		}
		return (int) $number;
	}

	/**
	 * Set file meta.
	 *
	 * @param int    $offset Offset.
	 * @param int    $file_size File size.
	 * @param string $file_path File path.
	 * @param string $location Location.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return $this
	 */
	public function set_meta( $offset, $file_size, $file_path, $location = null ) {
		$offset    = $this->ensure_integer( $offset );
		$file_size = $this->ensure_integer( $file_size );

		if ( ! is_string( $file_path ) ) {
			throw new InvalidArgumentException( '$file_path needs to be a string' );
		}

		$this->offset    = absint( $offset );
		$this->file_size = absint( $file_size );
		$this->file_path = $file_path;
		$this->location  = $location;

		return $this;
	}

	/**
	 * Set name.
	 *
	 * @param string $name Name.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 *
	 * @return $this
	 */
	public function set_name( $name ) {
		if ( ! is_string( $name ) ) {
			throw new InvalidArgumentException( '$name needs to be a string' );
		}
		$this->name = $name;

		return $this;
	}

	/**
	 * Get name.
	 *
	 * @return string
	 */
	public function get_name() {
		return $this->name;
	}

	/**
	 * Set file size.
	 *
	 * @param int $size The size.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return Tus_File
	 */
	public function set_file_size( $size ) {
		$size            = $this->ensure_integer( $size );
		$this->file_size = $size;

		return $this;
	}

	/**
	 * Get file size.
	 *
	 * @return int
	 */
	public function get_file_size() {
		return $this->file_size;
	}

	/**
	 * Set key.
	 *
	 * @param string $key The key.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return Tus_File
	 */
	public function set_key( $key ) {
		if ( ! is_string( $key ) ) {
			throw new InvalidArgumentException( '$key needs to be a string' );
		}
		$this->key = $key;

		return $this;
	}

	/**
	 * Get key.
	 *
	 * @return string
	 */
	public function get_key() {
		return $this->key;
	}

	/**
	 * Set checksum.
	 *
	 * @param string $checksum The checksum.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return Tus_File
	 */
	public function set_checksum( $checksum ) {
		if ( ! is_string( $checksum ) ) {
			throw new InvalidArgumentException( '$checksum needs to be a string' );
		}
		$this->checksum = $checksum;

		return $this;
	}

	/**
	 * Get checksum.
	 *
	 * @return string
	 */
	public function get_checksum() {
		return $this->checksum;
	}

	/**
	 * Set offset.
	 *
	 * @param int $offset The offset.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return self
	 */
	public function set_offset( $offset ) {
		$offset       = $this->ensure_integer( $offset );
		$this->offset = absint( $offset );

		return $this;
	}

	/**
	 * Get offset.
	 *
	 * @return int
	 */
	public function get_offset() {
		return $this->offset;
	}

	/**
	 * Set location.
	 *
	 * @param string $location The location.
	 *
	 * @throws InvalidArgumentException If argument is invalid.
	 * @return self
	 */
	public function set_location( $location ) {
		if ( ! is_string( $location ) ) {
			throw new InvalidArgumentException( '$location needs to be a string' );
		}
		$this->location = $location;

		return $this;
	}

	/**
	 * Get location.
	 *
	 * @return string
	 */
	public function get_location() {
		return $this->location;
	}

	/**
	 * Set absolute file location.
	 *
	 * @param string $path The path.
	 *
	 * @return Tus_File
	 */
	public function set_file_path( $path ) {
		$this->file_path = $path;

		return $this;
	}

	/**
	 * Get absolute location.
	 *
	 * @return string
	 */
	public function get_file_path() {
		return $this->file_path;
	}

	/**
	 * Set the upload meta.
	 *
	 * @param array $metadata The metadata.
	 *
	 * @return Tus_File
	 */
	public function set_upload_metadata( array $metadata ) {
		$this->upload_metadata = $metadata;

		return $this;
	}

	/**
	 * Get input stream.
	 *
	 * @return string
	 */
	public function get_input_stream() {
		return self::$input_stream;
	}

	/**
	 * Set input stream. Useful for testing.
	 *
	 * @param string $stream The stream.
	 *
	 * @return void
	 */
	public static function set_input_stream( $stream ) {
		self::$input_stream = $stream;
	}

	/**
	 * Get file meta.
	 *
	 * @return array
	 * @throws \Exception If date fails.
	 */
	public function details() {
		$now = Tus_Date_Utils::date_utc();
		$ttl = $this->cache->get_ttl();

		return array(
			'name'       => $this->name,
			'size'       => $this->file_size,
			'offset'     => $this->offset,
			'checksum'   => $this->checksum,
			'location'   => $this->location,
			'file_path'  => $this->file_path,
			'metadata'   => $this->upload_metadata,
			'created_at' => $now->format( Tus_Abstract_Cache::RFC_7231 ),
			'expires_at' => Tus_Date_Utils::add_seconds( $now, $ttl )->format( Tus_Abstract_Cache::RFC_7231 ),
		);
	}

	/**
	 * Upload file to server.
	 *
	 * @param int $total_bytes The total bytes of the file.
	 *
	 * @return int
	 * @throws Out_Of_Range_Exception Various exceptions.
	 * @throws Connection_Exception Various exceptions.
	 * @throws File_Exception Various exceptions.
	 */
	public function upload( $total_bytes ) {
		if ( $this->offset === $total_bytes ) {
			return $this->offset;
		}

		try {
					$input  = $this->open( $this->get_input_stream(), self::READ_BINARY );
					$output = $this->open( $this->get_file_path(), self::APPEND_BINARY );
					$key    = $this->get_key();
		} catch ( File_Exception $fe ) {
			Logger::log( 'error', $fe );
			throw new File_Exception( 'Upload failed.' );
		}

		try {
			$this->seek( $output, $this->offset );

			while ( ! feof( $input ) ) {
				if ( CONNECTION_NORMAL !== connection_status() ) {
					throw new Connection_Exception( 'Connection aborted by user.' );
				}

				$data  = $this->read( $input, self::CHUNK_SIZE );
				$bytes = $this->write( $output, $data, self::CHUNK_SIZE );

				$this->offset += $bytes;

				$this->cache->set( $key, array( 'offset' => $this->offset ) );

				if ( $this->offset > $total_bytes ) {
					throw new Out_Of_Range_Exception( 'The uploaded file is corrupt.' );
				}

				if ( $this->offset === $total_bytes ) {
					break;
				}
			}
		} finally {
			$this->close( $input );
			$this->close( $output );
		}

		return $this->offset;
	}

	/**
	 * Open file in given mode.
	 *
	 * @param string $file_path The file path.
	 * @param string $mode The mode.
	 *
	 * @return resource
	 * @throws File_Exception Exc.
	 * @throws InvalidArgumentException If argument is invalid.
	 */
	public function open( $file_path, $mode ) {
		if ( ! is_string( $file_path ) ) {
			throw new InvalidArgumentException( '$file_path needs to be a string' );
		}
		if ( ! is_string( $mode ) ) {
			throw new InvalidArgumentException( '$mode needs to be a string' );
		}
		$this->exists( $file_path, $mode );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged
		$ptr = @fopen( $file_path, $mode );

		if ( false === $ptr ) {
			Logger::log( 'error', "Unable to open file at $file_path." );
			throw new File_Exception( 'Unable to open file.' );
		}

		return $ptr;
	}

	/**
	 * Check if file to read exists.
	 *
	 * @param string $file_path The file path.
	 * @param string $mode The mode.
	 *
	 * @return bool
	 * @throws File_Exception File.
	 * @throws InvalidArgumentException If argument is invalid.
	 */
	public function exists( $file_path, $mode = self::READ_BINARY ) {
		if ( ! is_string( $file_path ) ) {
			throw new InvalidArgumentException( '$file_path needs to be a string' );
		}
		if ( self::INPUT_STREAM === $file_path ) {
			return true;
		}

		if ( self::READ_BINARY === $mode && ! file_exists( $file_path ) ) {
			throw new File_Exception( 'File not found.' );
		}

		return true;
	}

	/**
	 * Move file pointer to given offset using fseek.
	 *
	 * @param resource $handle The handle.
	 * @param int      $offset The offset.
	 * @param int      $whence The whence.
	 *
	 * @throws File_Exception Exc.
	 *
	 * @return int
	 */
	public function seek( $handle, $offset, $whence = SEEK_SET ) {
		$offset   = $this->ensure_integer( $offset );
		$position = fseek( $handle, $offset, $whence );

		if ( -1 === $position ) {
			throw new File_Exception( 'Cannot move pointer to desired position.' );
		}

		return $position;
	}

	/**
	 * Read data from file.
	 *
	 * @param resource $handle The handle.
	 * @param int      $chunk_size Chunk size.
	 *
	 * @return string
	 * @throws File_Exception If no data is read.
	 */
	public function read( $handle, $chunk_size ) {
		$chunk_size = $this->ensure_integer( $chunk_size );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
		$data = fread( $handle, $chunk_size );

		if ( false === $data ) {
			throw new File_Exception( 'Cannot read file.' );
		}

		return (string) $data;
	}

	/**
	 * Write data to file.
	 *
	 * @param resource $handle The file handle.
	 * @param string   $data The data to write.
	 * @param int|null $length Possibly the length of the data.
	 *
	 * @throws File_Exception When can't write.
	 *
	 * @return int
	 */
	public function write( $handle, $data, $length = null ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		$bytes_written = \is_numeric( $length ) ? fwrite( $handle, $data, intval( $length ) ) : fwrite( $handle, $data );

		if ( false === $bytes_written ) {
			throw new File_Exception( 'Cannot write to a file.' );
		}

		return $bytes_written;
	}

	/**
	 * Merge 2 or more files.
	 *
	 * @param array $files File data with meta info.
	 *
	 * @return int
	 * @throws File_Exception When the file to be merged is not found.
	 */
	public function merge( array $files ) {
		$destination = $this->get_file_path();
		$first_file  = array_shift( $files );

		// First partial file can directly be copied.
		$this->copy( $first_file['file_path'], $destination );

		$this->offset    = $first_file['offset'];
		$this->file_size = filesize( $first_file['file_path'] );

		$handle = $this->open( $destination, self::APPEND_BINARY );

		foreach ( $files as $file ) {
			if ( ! file_exists( $file['file_path'] ) ) {
				throw new File_Exception( 'File to be merged not found.' );
			}

			$this->file_size += $this->write( $handle, $this->get_wp_filesystem()->get_contents( $file['file_path'] ) );

			$this->offset += $file['offset'];
		}

		$this->close( $handle );

		return $this->file_size;
	}

	/**
	 * Copy file from source to destination.
	 *
	 * @param string $source The source.
	 * @param string $destination The destination.
	 *
	 * @return bool
	 * @throws File_Exception If copy fails.
	 */
	public function copy( $source, $destination ) {
		$status = copy( $source, $destination );

		if ( false === $status ) {
			Logger::log( 'error', sprintf( 'Cannot copy source (%s) to destination (%s).', $source, $destination ) );
			throw new File_Exception( 'Cannot copy source file to destination file.' );
		}

		return $status;
	}

	/**
	 * Delete file and/or folder.
	 *
	 * @param array $files The files.
	 * @param bool  $folder The folder.
	 *
	 * @return bool
	 */
	public function delete( array $files, $folder = false ) {
		$status = $this->delete_files( $files );

		if ( $status && $folder ) {
			return $this->get_wp_filesystem()->rmdir( \dirname( current( $files ) ) );
		}

		return $status;
	}

	/**
	 * Delete multiple files.
	 *
	 * @param array $files The files.
	 *
	 * @return bool
	 */
	public function delete_files( array $files ) {
		if ( empty( $files ) ) {
			return false;
		}

		$status = true;

		foreach ( $files as $file ) {
			if ( $this->get_wp_filesystem()->exists( $file ) ) {
				$r      = $this->get_wp_filesystem()->delete( $file );
				$status = $status && $r;
			}
		}

		return $status;
	}

	/**
	 * Close file.
	 *
	 * @param mixed $handle The handle.
	 *
	 * @return bool
	 */
	public function close( $handle ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return fclose( $handle );
	}

	/**
	 * Get the wp filesystem.
	 *
	 * @return \WP_Filesystem_Direct
	 */
	private function get_wp_filesystem() {
		global $wp_filesystem;

		if ( ! isset( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		return $wp_filesystem;
	}
}
