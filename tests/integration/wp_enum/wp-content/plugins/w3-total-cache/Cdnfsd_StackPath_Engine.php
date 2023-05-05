<?php
namespace W3TC;



class Cdnfsd_StackPath_Engine {
	private $api_key;
	private $zone_id;



	function __construct( $config = array() ) {
		$this->api_key = $config['api_key'];
		$this->zone_id = $config['zone_id'];
	}



	function flush_urls( $urls ) {
		if ( empty( $this->api_key ) || empty( $this->zone_id ) )
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );

		$api = Cdn_StackPath_Api::create( $this->api_key );

		$files = array();
		foreach ( $urls as $url ) {
			$parsed = parse_url( $url );
			$relative_url =
				( isset( $parsed['path'] ) ? $parsed['path'] : '/' ) .
				( isset( $parsed['query'] ) ? '?' . $parsed['query'] : '' );
			$files[] = $relative_url;
		}
		$api->delete_site_cache( $this->zone_id, $files );
	}



	/**
	 * Flushes CDN completely
	 */
	function flush_all() {
		if ( empty( $this->api_key ) || empty( $this->zone_id ) )
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );

		$api = Cdn_StackPath_Api::create( $this->api_key );
		$api->delete_site_cache( $this->zone_id );
	}
}
