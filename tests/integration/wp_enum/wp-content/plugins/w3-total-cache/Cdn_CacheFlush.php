<?php
namespace W3TC;

/**
 * CDN cache purge object
 */

/**
 * class Cdn_CacheFlush
 */
class Cdn_CacheFlush {
	/**
	 * Advanced cache config
	 */
	var $_config = null;


	/**
	 * Array of urls to flush
	 *
	 * @var array
	 */
	private $flush_operation_requested = false;

	/**
	 * PHP5 Constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Purges everything from CDNs that supports it
	 */
	function purge_all() {
		$this->flush_operation_requested = true;
		return true;
	}

	/**
	 * Purge a single url
	 *
	 * @param unknown $url
	 */
	function purge_url( $url ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$results = array();
		$files = array();
		$parsed = parse_url( $url );
		$local_site_path = isset( $parsed['path'] )? ltrim( $parsed['path'], '/' ) : '';
		$remote_path = $common->uri_to_cdn_uri( $local_site_path );
		$files[] = $common->build_file_descriptor( $local_site_path, $remote_path );
		$this->_flushed_urls[] = $url;
		$common->purge( $files, $results );
	}

	/**
	 * Clears global and repeated urls
	 */
	function purge_post_cleanup() {
		if ( $this->flush_operation_requested ) {
			$common = Dispatcher::component( 'Cdn_Core' );
			$results = array();
			$common->purge_all( $results );

			$count = 999;

			$this->flush_operation_requested = false;
		}

		return $count;
	}
}
