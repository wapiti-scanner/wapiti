<?php
namespace W3TC;



class Cdnfsd_StackPath2_Engine {
	private $config;



	function __construct( $config = array() ) {
		$this->config = $config;
	}



	function flush_urls( $urls ) {
		if ( empty( $this->config['client_id'] ) ) {
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );
		}

		$api = new Cdn_StackPath2_Api( $this->config );

		$items = array();
		foreach ( $urls as $url ) {
			$items[] = array( 'url' => $url,
				'recursive' => true,
			);
		}

		try {
			$api->purge( array( 'items' => $items ) );
		} catch ( \Exception $ex ) {
			if ( $ex->getMessage() == 'Validation Failure: Purge url must contain one of your hostnames' ) {
				throw new \Exception('CDN site is not configured correctly: Delivery Domain must match your site domain');
			} else {
				throw $ex;
			}
		}
	}



	/**
	 * Flushes CDN completely
	 */
	function flush_all() {
		if ( empty( $this->config['client_id'] ) ) {
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );
		}

		$api = new Cdn_StackPath2_Api( $this->config );

		$items = array();
		$items[] = array( 'url' => home_url( '/' ),
			'recursive' => true,
		);

		try {
			$r = $api->purge( array( 'items' => $items ) );
		} catch ( \Exception $ex ) {
			if ( $ex->getMessage() == 'Validation Failure: Purge url must contain one of your hostnames' ) {
				throw new \Exception('CDN site is not configured correctly: Delivery Domain must match your site domain');
			} else {
				throw $ex;
			}
		}
	}
}
