<?php
namespace W3TC;



class Cdnfsd_LimeLight_Engine {
	private $short_name;
	private $username;
	private $api_key;
	private $debug;



	function __construct( $config = array() ) {
		$this->short_name = $config['short_name'];
		$this->username = $config['username'];
		$this->api_key = $config['api_key'];
		$this->debug = $config['debug'];
	}



	function flush_urls( $urls ) {
		if ( empty( $this->short_name ) || empty( $this->username ) ||
			empty( $this->api_key ) )
			throw new \Exception( __( 'Credentials are not specified.', 'w3-total-cache' ) );

		$api = new Cdnfsd_LimeLight_Api( $this->short_name, $this->username, $this->api_key );
		$items = array();

		foreach ( $urls as $url ) {
			$items[] = array(
				'pattern' => $url,
				'exact' => true,
				'evict' => false,
				'incqs' => false
			);

			// max number of items per request based on API docs
			if ( count( $items ) >= 100 ) {
				if ( $this->debug ) {
					Util_Debug::log( 'cdnfsd', json_encode( $items, JSON_PRETTY_PRINT ) );
				}

				$api->purge( $items );
				$items = array();
			}
		}

		if ( $this->debug ) {
			Util_Debug::log( 'cdnfsd', json_encode( $items, JSON_PRETTY_PRINT ) );
		}

		$api->purge( $items );
	}



	/**
	 * Flushes CDN completely
	 */
	function flush_all() {
		if ( empty( $this->short_name ) || empty( $this->username ) ||
			empty( $this->api_key ) )
			throw new \Exception( __( 'Access key not specified.', 'w3-total-cache' ) );

		$api = new Cdnfsd_LimeLight_Api( $this->short_name, $this->username, $this->api_key );
		$url = Util_Environment::home_domain_root_url() . '/*';

		$items = array(
			array(
				'pattern' => $url,
				'exact' => false,
				'evict' => false,
				'incqs' => false
			)
		);

		if ( $this->debug ) {
			Util_Debug::log( 'cdnfsd', json_encode( $items, JSON_PRETTY_PRINT ) );
		}

		$api->purge( $items );
	}
}
