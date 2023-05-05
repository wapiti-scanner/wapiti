<?php
namespace W3TC;

class CdnEngine_Mirror_StackPath extends CdnEngine_Mirror {
	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		$config = array_merge( array(
				'authorization_key' => '',
				'alias' => '',
				'consumerkey' => '',
				'consumersecret' => '',
				'zone_id' => 0
			), $config );
		$split_keys = explode( '+', $config['authorization_key'] );
		if ( sizeof( $split_keys )==3 )
			list( $config['alias'], $config['consumerkey'], $config['consumersecret'] ) = $split_keys;
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
		if ( empty( $this->_config['authorization_key'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Empty Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		if ( empty( $this->_config['alias'] ) ||
			empty( $this->_config['consumerkey'] ) ||
			empty( $this->_config['consumersecret'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Malformed Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		$api = new Cdn_StackPath_Api( $this->_config['alias'],
			$this->_config['consumerkey'], $this->_config['consumersecret'] );
		$results = array();

		try {
			$zone_id = $this->_config['zone_id'];

			if ( $zone_id == 0 || is_null( $zone_id ) ) {
				$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_ERROR,
					__( 'No zone defined', 'w3-total-cache' ) );
				return !$this->_is_error( $results );
			}


			$files_to_pass = array();
			foreach ( $files as $file )
				$files_to_pass[] = '/' . $file['remote_path'];
			$params = array( 'files' => $files_to_pass );
			$api->delete_site_cache( $zone_id, $params );

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
		if ( empty( $this->_config['authorization_key'] ) ) {
			$results = $this->_get_results( array(), W3TC_CDN_RESULT_HALT,  __( 'Empty Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		if ( empty( $this->_config['alias'] ) || empty( $this->_config['consumerkey'] ) || empty( $this->_config['consumersecret'] ) ) {
			$results = $this->_get_results( array(), W3TC_CDN_RESULT_HALT,  __( 'Malformed Authorization Key.', 'w3-total-cache' ) );

			return false;
		}

		$api = new Cdn_StackPath_Api( $this->_config['alias'], $this->_config['consumerkey'], $this->_config['consumersecret'] );

		$results = array();

		try {
			$zone_id = $this->_config['zone_id'];

			if ( $zone_id == 0 || is_null( $zone_id ) ) {
				$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_ERROR,
					__( 'No zone defined', 'w3-total-cache' ) );
				return !$this->_is_error( $results );
			}

			$file_purge = $api->delete_site_cache( $zone_id );
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT, __( 'Failure to pull zone: ', 'w3-total-cache' ) . $e->getMessage() );
		}

		return !$this->_is_error( $results );
	}
}
