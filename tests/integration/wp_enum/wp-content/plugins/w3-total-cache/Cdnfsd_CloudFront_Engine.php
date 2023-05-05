<?php
namespace W3TC;

if ( !defined( 'W3TC_SKIPLIB_AWS' ) ) {
	require_once W3TC_DIR . '/vendor/autoload.php';
}



class Cdnfsd_CloudFront_Engine {
	private $access_key;
	private $secret_key;
	private $distribution_id;



	public function __construct( $config = array() ) {
		$this->access_key = $config['access_key'];
		$this->secret_key = $config['secret_key'];
		$this->distribution_id = $config['distribution_id'];
	}



	public function flush_urls( $urls ) {
		$api = $this->_api();

		$uris = array();
		foreach ( $urls as $url ) {
			$parsed = parse_url( $url );
			$relative_url =
				( isset( $parsed['path'] ) ? $parsed['path'] : '/' ) .
				( isset( $parsed['query'] ) ? '?' . $parsed['query'] : '' );
			$uris[] = $relative_url;
		}

		$api->createInvalidation( array(
				'DistributionId' => $this->distribution_id,
				'InvalidationBatch' => array(
					'CallerReference' => 'w3tc-' . 	microtime(),
					'Paths' => array(
						'Items' => $uris,
						'Quantity' => count( $uris ),
					),
				)
			)
		);
	}



	/**
	 * Flushes CDN completely
	 */
	public function flush_all() {
		$api = $this->_api();
		$uris = apply_filters( 'w3tc_cdn_cf_flush_all_uris', array( '/*' ) );

		$api->createInvalidation( array(
				'DistributionId' => $this->distribution_id,
				'InvalidationBatch' => array(
					'CallerReference' => 'w3tc-' . 	microtime(),
					'Paths' => array(
						'Items' => $uris,
						'Quantity' => count( $uris ),
					),
				)
			)
		);
	}



	private function _api() {
		if ( empty( $this->distribution_id ) ) {
			throw new \Exception( __('CloudFront distribution not specified.', 'w3-total-cache' ) );
		}

		if ( empty( $this->access_key ) && empty( $this->secret_key ) ) {
			$credentials = \Aws\Credentials\CredentialProvider::defaultProvider();
		} else {
			if ( empty( $this->access_key ) ) {
				throw new \Exception( __( 'Access key not specified.', 'w3-total-cache' ) );
			}

			if ( empty( $this->secret_key ) ) {
				throw new \Exception( __( 'Secret key not specified.', 'w3-total-cache' ) );
			}

			$credentials = new \Aws\Credentials\Credentials(
				$this->access_key, $this->secret_key );
		}

		return new \Aws\CloudFront\CloudFrontClient( array(
				'credentials' => $credentials,
				'region' => 'us-east-1',
				'version' => '2018-11-05'
			)
		);
	}
}
