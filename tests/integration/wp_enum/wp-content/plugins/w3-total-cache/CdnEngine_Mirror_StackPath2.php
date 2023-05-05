<?php
namespace W3TC;

class CdnEngine_Mirror_StackPath2 extends CdnEngine_Mirror {
	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		$config = array_merge( array(
				'client_id' => '',
				'client_secret' => '',
				'stack_id' => '',
				'site_root_domain' => '',
				'access_token' => '',
				'on_new_access_token' => null
			), $config );

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
		if ( empty( $this->_config['client_id'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Empty Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		$url_prefixes = $this->url_prefixes();
		$api = new Cdn_StackPath2_Api( $this->_config );
		$results = array();

		try {
			$items = array();
			foreach ( $files as $file ) {
				foreach ( $url_prefixes as $prefix ) {
					$items[] = array( 'url' => $prefix . '/' . $file['remote_path'],
						'recursive' => true,
					);
				}
			}
			$api->purge( array( 'items' => $items ) );

			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_OK, 'OK' );
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT, __( 'Failure to pull zone: ', 'w3-total-cache' ) . $e->getMessage() );
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
		if ( empty( $this->_config['client_id'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Empty Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		$url_prefixes = $this->url_prefixes();
		$api = new Cdn_StackPath2_Api( $this->_config );
		$results = array();

		try {
			$items = array();
			foreach ( $url_prefixes as $prefix ) {
				$items[] = array( 'url' => $prefix . '/',
					'recursive' => true,
				);
			}

			$r = $api->purge( array( 'items' => $items ) );
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT, __( 'Failure to pull zone: ', 'w3-total-cache' ) . $e->getMessage() );
		}

		return !$this->_is_error( $results );
	}



	private function url_prefixes() {
		$url_prefixes = array();

		if ( $this->_config['ssl'] == 'auto' ||
			$this->_config['ssl'] == 'enabled' ) {
			$url_prefixes[] = 'https://' . $this->_config['site_root_domain'];
		}
		if ( $this->_config['ssl'] == 'auto' ||
			$this->_config['ssl'] != 'enabled' ) {
			$url_prefixes[] = 'http://' . $this->_config['site_root_domain'];
		}

		return $url_prefixes;
	}
}
