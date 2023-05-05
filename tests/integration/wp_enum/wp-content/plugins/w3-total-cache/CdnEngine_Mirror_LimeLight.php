<?php
namespace W3TC;

/**
 * class CdnEngine_Mirror_Highwinds
 */
class CdnEngine_Mirror_LimeLight extends CdnEngine_Mirror {
	private $short_name;
	private $username;
	private $api_key;
	private $debug;
	private $domains;

	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 * account_hash
	 * username
	 * password
	 */
	function __construct( $config = array() ) {
		$this->short_name = $config['short_name'];
		$this->username = $config['username'];
		$this->api_key = $config['api_key'];
		$this->debug = $config['debug'];

		$this->domains = (array)$config['domains'];

		parent::__construct( $config );
	}

	/**
	 * Purges remote files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function purge( $files, &$results ) {
		if ( empty( $this->short_name ) || empty( $this->username ) ||
			empty( $this->api_key ) )
			throw new \Exception( __( 'Credentials are not specified.', 'w3-total-cache' ) );

		$api = new Cdnfsd_LimeLight_Api( $this->short_name, $this->username, $this->api_key );

		$results = array();
		try {
			$items = array();
			foreach ( $files as $file ) {
				$url = $this->_format_url( $file['remote_path'] );
				$items[] = array(
					'pattern' => $url,
					'exact' => true,
					'evict' => false,
					'incqs' => false
				);

				// max number of items per request based on API docs
				if ( count( $items ) >= 100 ) {
					if ( $this->debug ) {
						Util_Debug::log( 'cdn', json_encode( $items, JSON_PRETTY_PRINT ) );
					}

					$api->purge( $items );
					$items = array();
				}
			}

			if ( $this->debug ) {
				Util_Debug::log( 'cdn', json_encode( $items, JSON_PRETTY_PRINT ) );
			}

			$api->purge( $items );

			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_OK, 'OK' );
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT,
				__( 'Failed to purge: ', 'w3-total-cache' ) . $e->getMessage() );
		}

		return !$this->_is_error( $results );
	}

	/**
	 * Purge CDN completely
	 *
	 * @param unknown $results
	 * @return bool
	 */
	function purge_all( &$results ) {
		if ( empty( $this->short_name ) || empty( $this->username ) ||
			empty( $this->api_key ) )
			throw new \Exception( __( 'Access key not specified.', 'w3-total-cache' ) );

		$api = new Cdnfsd_LimeLight_Api( $this->short_name, $this->username, $this->api_key );

		$results = array();
		try {
			$items = array();
			foreach ( $this->domains as $domain ) {
				$items[] = array(
					'pattern' => 'http://' . $domain . '/*',
					'exact' => false,
					'evict' => false,
					'incqs' => false
				);
				$items[] = array(
					'pattern' => 'https://' . $domain . '/*',
					'exact' => false,
					'evict' => false,
					'incqs' => false
				);
			}

			if ( $this->debug ) {
				Util_Debug::log( 'cdn', json_encode( $items, JSON_PRETTY_PRINT ) );
			}

			$api->purge( $items );

			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_OK, 'OK' );
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT,
				__( 'Failed to purge all: ', 'w3-total-cache' ) . $e->getMessage() );
		}

		return !$this->_is_error( $results );
	}



	function get_domains() {
		return $this->domains;
	}
}
