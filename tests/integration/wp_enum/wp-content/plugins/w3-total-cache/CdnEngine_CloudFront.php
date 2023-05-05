<?php
namespace W3TC;

if ( !defined( 'W3TC_SKIPLIB_AWS' ) ) {
	require_once W3TC_DIR . '/vendor/autoload.php';
}

/**
 * Amazon CloudFront (S3 origin) CDN engine
 */
class CdnEngine_CloudFront extends CdnEngine_Base {
	private $s3;
	private $api;

	function __construct( $config = array() ) {
		$config = array_merge( array(
				'id' => ''
			), $config );

		parent::__construct( $config );

		$this->s3 = new CdnEngine_S3( $config );
	}

	/**
	 * Initialize
	 */
	function _init() {
		if ( !is_null( $this->api ) ) {
			return;
		}

		if ( empty( $this->_config['key'] ) && empty( $this->_config['secret'] ) ) {
			$credentials = \Aws\Credentials\CredentialProvider::defaultProvider();
		} else {
			$credentials = new \Aws\Credentials\Credentials(
				$this->_config['key'],
				$this->_config['secret'] );
		}

		$this->api = new \Aws\CloudFront\CloudFrontClient( array(
				'credentials' => $credentials,
				'region' => $this->_config['bucket_location'],
				'version' => '2018-11-05'
			)
		);

		return true;
	}

	/**
	 * Formats URL
	 */
	function _format_url( $path ) {
		$domain = $this->get_domain( $path );

		if ( $domain ) {
			$scheme = $this->_get_scheme();

			// it does not support '+', requires '%2B'
			$path = str_replace( '+', '%2B', $path );
			$url = sprintf( '%s://%s/%s', $scheme, $domain, $path );

			return $url;
		}

		return false;
	}

	/**
	 * Upload files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @param boolean $force_rewrite
	 * @return boolean
	 */
	function upload( $files, &$results, $force_rewrite = false,
		$timeout_time = NULL ) {
		return $this->s3->upload( $files, $results, $force_rewrite,
			$timeout_time );
	}

	/**
	 * Delete files from CDN
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function delete( $files, &$results ) {
		return $this->s3->delete( $files, $results );
	}

	/**
	 * Purge files from CDN
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function purge( $files, &$results ) {
		if ( !$this->s3->upload( $files, $results, true ) ) {
			return false;
		}

		try {
			$this->_init();
			$dist = $this->_get_distribution();
		} catch ( \Exception $ex ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, $ex->getMessage() );
			return false;
		}

		$paths = array();

		foreach ( $files as $file ) {
			$remote_file = $file['remote_path'];
			$paths[] = '/' . $remote_file;
		}

		try {
			$invalidation = $this->api->createInvalidation( array(
					'DistributionId' => $dist['Id'],
					'InvalidationBatch' => array(
						'CallerReference' => 'w3tc-' . 	microtime(),
						'Paths' => array(
							'Items' => $paths,
							'Quantity' => count( $paths ),
						),
					)
				)
			);
		} catch ( \Exception $ex ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT,
				sprintf( 'Unable to create invalidation batch (%s).',
				$ex->getMessage() ) );

			return false;
		}

		$results = $this->_get_results( $files, W3TC_CDN_RESULT_OK, 'OK' );
		return true;
	}

	/**
	 * Returns origin
	 */
	function _get_origin() {
		if ( $this->_config['bucket_location'] === 'us-east-1' ) {
			$region = "";
		} else {
			$region = $this->_config['bucket_location'] . '.';
		}
		return sprintf( '%s.s3.%samazonaws.com', $this->_config['bucket'], $region );
	}

	/**
	 * Returns array of CDN domains
	 */
	public function get_domains() {
		if ( !empty( $this->_config['cname'] ) ) {
			return (array) $this->_config['cname'];
		} elseif ( !empty( $this->_config['id'] ) ) {
			$domain = sprintf( '%s.cloudfront.net', $this->_config['id'] );

			return array(
				$domain
			);
		}

		return array();
	}

	/**
	 * Test CDN connectivity
	 */
	function test( &$error ) {
		$this->_init();
		if ( !$this->s3->test( $error ) ) {
			return false;
		}

		/**
		 * Search active CF distribution
		 */
		$dists = $this->api->listDistributions();

		if ( !isset( $dists['DistributionList']['Items'] ) ) {
			$error = 'Unable to list distributions.';
			return false;
		}

		if ( !count( $dists['DistributionList']['Items'] ) ) {
			$error = 'No distributions found.';

			return false;
		}

		$dist = $this->_get_distribution( $dists );
		if ( $dist["Status"] != 'Deployed' ) {
			$error = sprintf( 'Distribution status is not Deployed, but "%s".', $dist["Status"] );
			return false;
		}

		if ( !$dist['Enabled'] ) {
			$error = sprintf( 'Distribution for origin "%s" is disabled.', $origin );
			return false;
		}

		if ( !empty( $this->_config['cname'] ) ) {
			$domains = (array) $this->_config['cname'];
			$cnames = ( isset( $dist['Aliases']['Items'] ) ? (array) $dist['Aliases']['Items'] : array() );

			foreach ( $domains as $domain ) {
				$_domains = array_map( 'trim', explode( ',', $domain ) );

				foreach ( $_domains as $_domain ) {
					if ( !in_array( $_domain, $cnames ) ) {
						$error = sprintf( 'Domain name %s is not in distribution <acronym title="Canonical Name">CNAME</acronym> list.', $_domain );

						return false;
					}
				}
			}
		} elseif ( !empty( $this->_config['id'] ) ) {
			$domain = $this->get_domain();

			if ( $domain != $dist['DomainName'] ) {
				$error = sprintf( 'Distribution domain name mismatch (%s != %s).', $domain, $dist['DomainName'] );

				return false;
			}
		}

		return true;
	}

	/**
	 * Create bucket
	 */
	function create_container() {
		$this->_init();
		$this->s3->create_container();

		// plugin cant set CNAMEs list since it CloudFront requires
		// certificate to be specified associated with it
		$cnames = array();

		// make distibution
		$originDomain = $this->_get_origin();

		try {
			$result = $this->api->createDistribution(array(
				'DistributionConfig' => array(
					'CallerReference' => $originDomain,
					'Comment' => 'Created by W3-Total-Cache',
					'DefaultCacheBehavior' => array(
						'AllowedMethods' => array(
							'CachedMethods' => array(
								'Items' => array( 'HEAD', 'GET' ),
								'Quantity' => 2,
							),
							'Items' => array( 'HEAD', 'GET' ),
							'Quantity' => 2,
						),
						'Compress' => true,
						'DefaultTTL' => 86400,
						'FieldLevelEncryptionId' => '',
						'ForwardedValues' => array(
							'Cookies' => array(
								'Forward' => 'none',
							),
							'Headers' => array(
								'Quantity' => 0,
							),
							'QueryString' => false,
							'QueryStringCacheKeys' => array(
								'Quantity' => 0,
							),
						),
						'LambdaFunctionAssociations' => array( 'Quantity' => 0),
						'MinTTL' => 0,
						'SmoothStreaming' => false,
						'TargetOriginId' => $originDomain,
						'TrustedSigners' => array(
							'Enabled' => false,
							'Quantity' => 0,
						),
						'ViewerProtocolPolicy' => 'allow-all',
					),
					'Enabled' => true,
					'Origins' => array(
						'Items' => array(
							array(
								'DomainName' => $originDomain,
								'Id' => $originDomain,
								'OriginPath' => '',
								'CustomHeaders' => array( 'Quantity' => 0 ),
								'S3OriginConfig' => array(
									'OriginAccessIdentity' => ''
								),
							),
						),
						'Quantity' => 1,
					),
					'Aliases' => array(
						'Items' => $cnames,
						'Quantity' => count( $cnames )
					)
				)
			));

			// extract domain dynamic part stored later in a config
			$domain = $result['Distribution']['DomainName'];
			$container_id = '';
			if ( preg_match( '~^(.+)\.cloudfront\.net$~', $domain, $matches ) ) {
				$container_id = $matches[1];
			}

			return $container_id;

		} catch ( \Exception $ex ) {
			throw new \Exception( sprintf(
				'Unable to create distribution for origin %s: %s', $originDomain,
				$ex->getMessage() ) );
		}
	}

	/**
	 * Returns via string
	 *
	 * @return string
	 */
	function get_via() {
		$domain = $this->get_domain();
		$via = ( $domain ? $domain : 'N/A' );

		return sprintf( 'Amazon Web Services: CloudFront: %s', $via );
	}

	private function _get_distribution( $dists = null ) {
		if ( is_null( $dists ) ) {
			$dists = $this->api->listDistributions();
		}

		if ( !isset( $dists['DistributionList']['Items'] ) ||
				!count( $dists['DistributionList']['Items'] ) ) {
			throw new \Exception( 'No distributions found.' );
		}

		$dist = false;
		$origin = $this->_get_origin();

		$items = $dists['DistributionList']['Items'];
		foreach ( $items as $dist ) {
			if ( isset( $dist['Origins']['Items'] ) ) {
				foreach ( $dist['Origins']['Items'] as $o ) {
					if ( isset( $o['DomainName'] ) && $o['DomainName'] == $origin ) {
						return $dist;
					}
				}
			}
		}

		throw new \Exception( sprintf( 'Distribution for origin "%s" not found.', $origin ) );
	}
}
