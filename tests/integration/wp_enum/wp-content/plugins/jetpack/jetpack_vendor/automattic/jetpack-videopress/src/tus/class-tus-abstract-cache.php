<?php
/**
 * Main
 *
 * @package VideoPressUploader
 **/

namespace VideoPressUploader;

// Avoid direct calls to this file.
if ( ! defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Abstract cache class.
 **/
abstract class Tus_Abstract_Cache {

	/**
	 * Date format standard.
	 *
	 * @see https://tools.ietf.org/html/rfc7231#section-7.1.1.1
	 *
	 * @var int
	 **/
	const RFC_7231 = 'D, d M Y H:i:s \G\M\T';

	/**
	 * TTL in secs (default 1 day).
	 *
	 * @var int
	 **/
	protected $ttl = 86400;

	/** Prefix for cache keys.
	 *
	 * @var string
	 **/
	protected $prefix = 'videopress_uploader_1_';

	/**
	 * Various blog_id.
	 *
	 * @var string
	 */
	protected $blog_id = 'simple';

	/**
	 * Cache constructor.
	 *
	 * @param int|string $blog_id The blog_id.
	 */
	public function __construct( $blog_id ) {
		$this->blog_id = (string) $blog_id;
	}

	/**
	 * Cache Get key.
	 *
	 * @param string $key The blog_id.
	 *
	 * @return mixed|null
	 */
	abstract protected function cache_get( $key );

	/**
	 * Set data to the given key.
	 *
	 * @param string $key The key.
	 * @param mixed  $value The value.
	 * @param bool   $is_update Is update.
	 *
	 * @return mixed
	 */
	abstract public function cache_set( $key, $value, $is_update );

	/**
	 * Delete data associated with the key.
	 *
	 * @param string $key The key.
	 *
	 * @return bool
	 */
	abstract public function cache_delete( $key );

	/**
	 * Get cache keys.
	 *
	 * @param string $keys_prefix The key prefix.
	 *
	 * @return array
	 */
	abstract public function cache_keys( $keys_prefix );

	/**
	 * Build a cache key.
	 *
	 * @param string $key Key.
	 *
	 * @return string
	 */
	public function build_key( $key ) {
		$prefix = $this->get_prefix();

		if ( 0 !== strpos( $key, $prefix ) ) {
			$key = $prefix . $key;
		}

		return $key;
	}

	/**
	 * Get key.
	 *
	 * @param string $key The blog_id.
	 * @param bool   $with_expired Even get the expired keys.
	 *
	 * @return mixed|null
	 */
	public function get( $key, $with_expired = false ) {
		$key = $this->build_key( $key );

		$contents_str = $this->cache_get( $key );
		$contents     = json_decode( $contents_str, true );

		if ( ! $contents ) {
			return null;
		}

		if ( $with_expired ) {
			return $contents;
		}

		return $this->is_content_expired( $contents ) ? null : $contents;
	}

	/**
	 * Deletes a key.
	 *
	 * @param string $key The key.
	 *
	 * @return mixed
	 */
	public function delete( $key ) {
		$key = $this->build_key( $key );
		return $this->cache_delete( $key ) > 0;
	}

	/**
	 * Set cache key.
	 *
	 * @param string      $key The key.
	 * @param array|mixed $value Even get the expired key.
	 *
	 * @return bool
	 */
	public function set( $key, $value ) {
		$key        = $this->build_key( $key );
		$cache_data = $this->get( $key );
		$contents   = $cache_data ? $cache_data : array();

		if ( \is_array( $value ) ) {
			$contents = array_merge( $contents, $value );
		} else {
			$contents[] = $value;
		}

		$status = $this->cache_set( $key, \wp_json_encode( $contents ), ! empty( $cache_data ) );
		return false !== $status;
	}

	/**
	 * Get cache keys.
	 *
	 * @return array
	 */
	public function keys() {
		// TODO: This needs more thought.
		$keys_entry = $this->cache_keys( 'videopress_cache_keys_blog_' . $this->blog_id );
		return json_decode( $keys_entry );
	}

	/**
	 * Delete all data associated with the keys.
	 *
	 * @param array $keys The keys to delete.
	 *
	 * @return bool
	 */
	public function delete_all( $keys ) {
		$status = true;

		foreach ( $keys as $key ) {
			$r      = $this->delete( $this->build_key( $key ) );
			$status = $status && $r;
		}

		return $status;
	}

	/**
	 * Get time to live.
	 *
	 * @return int
	 */
	public function get_ttl() {
		return $this->ttl;
	}

	/**
	 * Set time to live.
	 *
	 * @param int $secs The ttl.
	 *
	 * @return self
	 */
	public function set_ttl( $secs ) {
		$this->ttl = $secs;

		return $this;
	}

	/**
	 * Set cache prefix.
	 *
	 * @param string $prefix The prefix.
	 *
	 * @return self
	 */
	public function set_prefix( $prefix ) {
		$this->prefix = $prefix;
		return $this;
	}

	/**
	 * Get cache prefix.
	 *
	 * @return string
	 */
	public function get_prefix() {
		/**
		 * Filters the cache prefix that will be used for VideoPress Uploader.
		 *
		 * @param string $cache_prefix The cache prefix.
		 *
		 * @return string
		 */
		return apply_filters( 'videopress_uploader_cache_prefix', $this->prefix );
	}

	/**
	 * Log stuff
	 *
	 * @param string $what Stuff to log.
	 */
	protected function log( $what ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r
		do_action( 'videopress_uploader_log', 'info', get_class( $this ) . ' Cache Store: \n\n' . print_r( $what, true ) );
	}

	/**
	 * Checks if content has an expires_at entry and compares to time().
	 *
	 * @param array $contents The contents.
	 *
	 * @return bool
	 **/
	protected function is_content_expired( $contents ) {
		if ( ! isset( $contents['expires_at'] ) ) {
			return false;
		}

		$expires_at = $contents['expires_at'];
		$date       = Tus_Date_Utils::date_utc( $expires_at );

		return absint( $date->getTimestamp() ) < time();
	}
}
