<?php
namespace W3TC;

/**
 * class Cache_File
 */
class Cache_File extends Cache_Base {
	/**
	 * Path to cache dir
	 *
	 * @var string
	 */
	protected $_cache_dir = '';

	/**
	 * Directory to flush
	 *
	 * @var string
	 */
	protected $_flush_dir = '';
	/**
	 * Exclude files
	 *
	 * @var array
	 */
	protected $_exclude = array();

	/**
	 * Flush time limit
	 *
	 * @var int
	 */
	protected $_flush_timelimit = 0;

	/**
	 * File locking
	 *
	 * @var boolean
	 */
	protected $_locking = false;

	/**
	 * If path should be generated based on wp_hash
	 *
	 * @var bool
	 */
	protected $_use_wp_hash = false;

	/**
	 * Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		parent::__construct( $config );
		if ( isset( $config['cache_dir'] ) )
			$this->_cache_dir = trim( $config['cache_dir'] );
		else
			$this->_cache_dir = Util_Environment::cache_blog_dir( $config['section'], $config['blog_id'] );

		$this->_exclude = isset( $config['exclude'] ) ? (array) $config['exclude'] : array();
		$this->_flush_timelimit = isset( $config['flush_timelimit'] ) ? (int) $config['flush_timelimit'] : 180;
		$this->_locking = isset( $config['locking'] ) ? (boolean) $config['locking'] : false;

		if ( isset( $config['flush_dir'] ) )
			$this->_flush_dir = $config['flush_dir'];
		else {
			if ( $config['blog_id'] <= 0 && !isset( $config['cache_dir'] ) ) {
				// clear whole section if we operate on master cache
				// and in a mode when cache_dir not strictly specified
				$this->_flush_dir = Util_Environment::cache_dir( $config['section'] );
			} else
				$this->_flush_dir = $this->_cache_dir;
		}
		if ( isset( $config['use_wp_hash'] ) && $config['use_wp_hash'] )
			$this->_use_wp_hash = true;
	}

	/**
	 * Adds data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function add( $key, &$var, $expire = 0, $group = '' ) {
		if ( $this->get( $key, $group ) === false ) {
			return $this->set( $key, $var, $expire, $group );
		}

		return false;
	}

	/**
	 * Sets data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function set( $key, $var, $expire = 0, $group = '' ) {
		$fp = $this->fopen_write( $key, $group, 'wb' );
		if ( !$fp )
			return false;

		if ( $this->_locking )
			@flock( $fp, LOCK_EX );

		if ( $expire <= 0 || $expire > W3TC_CACHE_FILE_EXPIRE_MAX )
			$expire = W3TC_CACHE_FILE_EXPIRE_MAX;

		$expires_at = time() + $expire;
		@fputs( $fp, pack( 'L', $expires_at ) );
		@fputs( $fp, '<?php exit; ?>' );
		@fputs( $fp, @serialize( $var ) );
		@fclose( $fp );

		if ( $this->_locking )
			@flock( $fp, LOCK_UN );

		return true;
	}

	/**
	 * Returns data
	 *
	 * @param string  $key
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return mixed
	 */
	function get_with_old( $key, $group = '' ) {
		list( $data, $has_old_data ) = $this->_get_with_old_raw( $key, $group );
		if ( !empty( $data ) )
			$data_unserialized = @unserialize( $data );
		else
			$data_unserialized = $data;

		return array( $data_unserialized, $has_old_data );
	}



	private function _get_with_old_raw( $key, $group = '' ) {
		$has_old_data = false;

		$storage_key = $this->get_item_key( $key );

		$path = $this->_cache_dir . DIRECTORY_SEPARATOR .
			( $group ? $group . DIRECTORY_SEPARATOR : '' ) .
			$this->_get_path( $storage_key, $group );
		if ( !is_readable( $path ) )
			return array( null, $has_old_data );

		$fp = @fopen( $path, 'rb' );
		if ( ! $fp || 4 > filesize( $path ) ) {
			return array( null, $has_old_data );
		}

		if ( $this->_locking )
			@flock( $fp, LOCK_SH );

		$expires_at = @fread( $fp, 4 );
		$data = null;

		if ( $expires_at !== false ) {
			list( , $expires_at ) = @unpack( 'L', $expires_at );

			if ( time() > $expires_at ) {
				if ( $this->_use_expired_data ) {
					// update expiration so other threads will use old data
					$fp2 = @fopen( $path, 'cb' );

					if ( $fp2 ) {
						@fputs( $fp2, pack( 'L', time() + 30 ) );
						@fclose( $fp2 );
					}
					$has_old_data = true;
				}
			} else {
				$data = '';

				while ( !@feof( $fp ) ) {
					$data .= @fread( $fp, 4096 );
				}
				$data = substr( $data, 14 );
			}

		}

		if ( $this->_locking )
			@flock( $fp, LOCK_UN );

		@fclose( $fp );

		return array( $data, $has_old_data );
	}

	/**
	 * Replaces data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function replace( $key, &$var, $expire = 0, $group = '' ) {
		if ( $this->get( $key, $group ) !== false ) {
			return $this->set( $key, $var, $expire, $group );
		}

		return false;
	}

	/**
	 * Deletes data
	 *
	 * @param string  $key
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function delete( $key, $group = '' ) {
		$storage_key = $this->get_item_key( $key );

		$path = $this->_cache_dir . DIRECTORY_SEPARATOR .
			( $group ? $group . DIRECTORY_SEPARATOR : '' ) .
			$this->_get_path( $storage_key, $group );

		if ( !file_exists( $path ) )
			return true;

		if ( $this->_use_expired_data ) {
			$fp = @fopen( $path, 'cb' );

			if ( $fp ) {
				if ( $this->_locking )
					@flock( $fp, LOCK_EX );

				@fputs( $fp, pack( 'L', 0 ) );   // make it expired
				@fclose( $fp );

				if ( $this->_locking )
					@flock( $fp, LOCK_UN );
				return true;
			}

		}

		return @unlink( $path );
	}

	/**
	 * Deletes _old and primary if exists.
	 *
	 * @param string  $key
	 *
	 * @return bool
	 */
	function hard_delete( $key, $group = '' ) {
		$key = $this->get_item_key( $key );
		$path = $this->_cache_dir . DIRECTORY_SEPARATOR . $this->_get_path( $key, $group );
		return @unlink( $path );
	}

	/**
	 * Flushes all data
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function flush( $group = '' ) {
		@set_time_limit( $this->_flush_timelimit );
		$flush_dir = $group ?
			$this->_cache_dir . DIRECTORY_SEPARATOR . $group .
			DIRECTORY_SEPARATOR :
			$this->_flush_dir;
		Util_File::emptydir( $flush_dir, $this->_exclude );
		return true;
	}

	/**
	 * Returns modification time of cache file
	 *
	 * @param integer $key
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean|string
	 */
	function mtime( $key, $group = '' ) {
		$path =
			$this->_cache_dir . DIRECTORY_SEPARATOR .
			( $group ? $group . DIRECTORY_SEPARATOR : '' ) .
			$this->_get_path( $key, $group );

		if ( file_exists( $path ) ) {
			return @filemtime( $path );
		}

		return false;
	}

	/**
	 * Returns file path for key
	 *
	 * @param string  $key
	 * @return string
	 */
	function _get_path( $key, $group = '' ) {
		if ( $this->_use_wp_hash && function_exists( 'wp_hash' ) )
			$hash = wp_hash( $key );
		else
			$hash = md5( $key );

		$path = sprintf( '%s/%s/%s.php', substr( $hash, 0, 3 ), substr( $hash, 3, 3 ), $hash );

		return $path;
	}

	public function get_stats_size( $timeout_time ) {
		$size = array(
			'bytes' => 0,
			'items' => 0,
			'timeout_occurred' => false
		);

		$size = $this->dirsize( $this->_cache_dir, $size, $timeout_time );
		return $size;
	}



	private function dirsize( $path, $size, $timeout_time ) {
		$dir = @opendir( $path );

		if ( $dir ) {
			while ( !$size['timeout_occurred'] && ( $entry = @readdir( $dir ) ) !== false ) {
				if ( $entry == '.' || $entry == '..' ) {
					continue;
				}

				$full_path = $path . DIRECTORY_SEPARATOR . $entry;

				if ( @is_dir( $full_path ) ) {
					$size = $this->dirsize( $full_path, $size, $timeout_time );
				} else {
					$size['bytes'] += @filesize( $full_path );

					// dont check time() for each file, quite expensive
					$size['items']++;
					if ( $size['items'] % 1000 == 0 )
						$size['timeout_occurred'] |= ( time() > $timeout_time );
				}
			}

			@closedir( $dir );
		}

		return $size;
	}

	/**
	 * Used to replace as atomically as possible known value to new one
	 */
	public function set_if_maybe_equals( $key, $old_value, $new_value ) {
		// cant guarantee atomic action here, filelocks fail often
		$value = $this->get( $key );
		if ( isset( $old_value['content'] ) &&
			$value['content'] != $old_value['content'] )
			return false;

		return $this->set( $key, $new_value );
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_add( $key, $value ) {
		if ( $value == 0 )
			return true;

		$fp = $this->fopen_write( $key, '', 'a' );
		if ( !$fp )
			return false;

		// use "x" to store increment, since it's most often case
		// and it will save 50% of size if only increments are used
		if ( $value == 1 )
			@fputs( $fp, 'x' );
		else
			@fputs( $fp, ' ' . (int)$value );

		@fclose( $fp );
		return true;
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_set( $key, $value ) {
		$fp = $this->fopen_write( $key, '', 'wb' );
		if ( !$fp )
			return false;

		$expire = W3TC_CACHE_FILE_EXPIRE_MAX;
		$expires_at = time() + $expire;

		@fputs( $fp, pack( 'L', $expires_at ) );
		@fputs( $fp, '<?php exit; ?>' );
		@fputs( $fp, (int)$value );
		@fclose( $fp );

		return true;
	}

	/**
	 * Get counter's value
	 */
	public function counter_get( $key ) {
		list( $value, $old_data ) = $this->_get_with_old_raw( $key );
		if ( empty( $value ) )
			return 0;

		$original_length = strlen( $value );
		$cut_value = str_replace( 'x', '', $value );

		$count = $original_length - strlen( $cut_value );

		// values more than 1 are stored as <space>value
		$a = explode( ' ', $cut_value );
		foreach ( $a as $counter_value )
			$count += (int)$counter_value;

		return $count;
	}

	private function fopen_write( $key, $group, $mode ) {
		$storage_key = $this->get_item_key( $key );

		$sub_path = $this->_get_path( $storage_key, $group );
		$path = $this->_cache_dir . DIRECTORY_SEPARATOR .
			( $group ? $group . DIRECTORY_SEPARATOR : '' ) . $sub_path;

		$dir = dirname( $path );

		if ( !@is_dir( $dir ) ) {
			if ( !Util_File::mkdir_from( $dir, dirname( W3TC_CACHE_DIR ) ) )
				return false;
		}

		$fp = @fopen( $path, $mode );
		return $fp;
	}
}
