<?php
/**
 * A static in-process cache for blog data.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack\Status;

/**
 * A static in-process cache for blog data.
 *
 * For internal use only. Do not use this externally.
 */
class Cache {
	/**
	 * Cached data;
	 *
	 * @var array[]
	 */
	private static $cache = array();

	/**
	 * Get a value from the cache.
	 *
	 * @param string $key Key to fetch.
	 * @param mixed  $default Default value to return if the key is not set.
	 * @returns mixed Data.
	 */
	public static function get( $key, $default = null ) {
		$blog_id = get_current_blog_id();
		return isset( self::$cache[ $blog_id ] ) && array_key_exists( $key, self::$cache[ $blog_id ] ) ? self::$cache[ $blog_id ][ $key ] : $default;
	}

	/**
	 * Set a value in the cache.
	 *
	 * @param string $key Key to set.
	 * @param mixed  $value Value to store.
	 */
	public static function set( $key, $value ) {
		$blog_id                         = get_current_blog_id();
		self::$cache[ $blog_id ][ $key ] = $value;
	}

	/**
	 * Clear the cache.
	 *
	 * This is intended for use in unit tests.
	 */
	public static function clear() {
		self::$cache = array();
	}

}
