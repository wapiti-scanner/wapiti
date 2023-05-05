<?php
namespace W3TC;

if ( !defined( 'W3TC_SKIPLIB_AWS' ) ) {
	require_once W3TC_DIR . '/vendor/autoload.php';
}

/**
 * Amazon CloudFront (mirror) CDN engine
 */
class CdnEngine_Mirror_CloudFront extends CdnEngine_Mirror {
	private $api;

	/**
	 * Constructor
	 */
	function __construct( $config = array() ) {
		parent::__construct( $config );
	}

	/**
	 * Initializes S3 object
	 *
	 * @param string  $error
	 * @return bool
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
				'region' => 'us-east-1',
				'version' => '2018-11-05'
			)
		);

		return true;
	}

	/**
	 * Returns origin
	 *
	 * @return string
	 */
	function _get_origin() {
		return Util_Environment::host_port();
	}

	/**
	 * Purge files from CDN
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function purge( $files, &$results ) {
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
	 * Purge CDN completely
	 *
	 * @param unknown $results
	 * @return bool
	 */
	function purge_all( &$results ) {
		return $this->purge( array( array( 'remote_path' => '*' ) ), $results );
	}

	/**
	 * Returns array of CDN domains
	 *
	 * @return array
	 */
	function get_domains() {
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
	 * Tests CF
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function test( &$error ) {
		$this->_init();

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
	 * Create distribution
	 */
	function create_container() {
		$this->_init();

		// plugin cant set CNAMEs list since it CloudFront requires
		// certificate to be specified associated with it
		$cnames = array();

		// make distibution
		$originDomain = $this->_get_origin();

		try {
			$result = $this->api->createDistribution( array(
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
								'CustomOriginConfig' => array(
									'HTTPPort' => 80,
									'HTTPSPort' => 443,
									'OriginProtocolPolicy' => 'match-viewer'
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

		} catch ( \Aws\Exception\AwsException $ex ) {
			throw new \Exception( sprintf(
				'Unable to create distribution for origin %s: %s', $originDomain,
				$ex->getAwsErrorMessage() ) );
		} catch ( \Exception $ex ) {
			throw new \Exception( sprintf(
				'Unable to create distribution for origin %s: %s', $originDomain,
				$ex->getMessage() ) );
		}
	}

	/**
	 * Returns via string
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
