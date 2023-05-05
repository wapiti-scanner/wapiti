<?php
/**
 * Transient Store.
 *
 * @package VideoPressUploader
 **/

namespace VideoPressUploader;

// Avoid direct calls to this file.
if ( ! defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Transient - based store.
 */
class Transient_Store extends Tus_Abstract_Cache {

	/**
	 * Get key.
	 *
	 * @param string $key The blog_id.
	 *
	 * @return mixed|null
	 */
	public function cache_get( $key ) {
		$contents = get_transient( $key, '' );
		return empty( $contents ) ? null : $contents;
	}

	/**
	 * Set cache key.
	 *
	 * @param string      $key The key.
	 * @param array|mixed $value Even get the expired key.
	 * @param bool        $is_update Is this an update.
	 *
	 * @return bool
	 */
	public function cache_set( $key, $value, $is_update = false ) {
		if ( $is_update ) {
			delete_transient( $key );
		}
		return set_transient( $key, $value, $this->get_ttl() );
	}

	/**
	 * Deletes a key.
	 *
	 * @param string $key The key.
	 *
	 * @return mixed
	 */
	public function cache_delete( $key ) {
		return delete_transient( $key );
	}

	/**
	 * Get cache keys.
	 *
	 * @param string $prefix Prefix.
	 *
	 * @return array
	 */
	public function cache_keys( $prefix ) {
		return get_transient( $prefix );
	}
}

