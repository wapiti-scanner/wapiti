<?php
namespace W3TC;

/**
 * Rackspace CDN (pull) engine
 */
class CdnEngine_Mirror_RackSpaceCdn extends CdnEngine_Mirror {
	private $_access_state;
	private $_service_id;
	private $_domains;
	private $_api;
	private $_new_access_state_callback;



	function __construct( $config = array() ) {
		$config = array_merge( array(
				'user_name' => '',
				'api_key' => '',
				'region' => '',
				'service_id' => '',
				'service_access_url' => '',
				'service_protocol' => 'http',
				'domains' => array(),
				'access_state' => '',
				'new_access_state_callback' => ''
			), $config );

		$this->_service_id = $config['service_id'];
		$this->_new_access_state_callback = $config['new_access_state_callback'];

		// init access state
		$this->_access_state = @json_decode( $config['access_state'], true );
		if ( !is_array( $this->_access_state ) )
			$this->_access_state = array();
		$this->_access_state = array_merge( array(
				'access_token' => '',
				'access_region_descriptor' => array()
			), $this->_access_state );

		// cnames
		if ( $config['service_protocol'] != 'https' && !empty( $config['domains'] ) )
			$this->_domains = (array)$config['domains'];
		else
			$this->_domains = array( $config['service_access_url'] );

		// form 'ssl' parameter based on service protocol
		if ( $config['service_protocol'] == 'https' )
			$config['ssl'] = 'enabled';
		else
			$config['ssl'] = 'disabled';

		parent::__construct( $config );
		$this->_create_api( array( $this, '_on_new_access_requested_api' ) );
	}



	private function _create_api( $new_access_required_callback_api ) {
		$this->_api = new Cdn_RackSpace_Api_Cdn( array(
				'access_token' => $this->_access_state['access_token'],
				'access_region_descriptor' => $this->_access_state['access_region_descriptor'],
				'new_access_required' => $new_access_required_callback_api ) );
	}



	/**
	 * Called when new access token issued by api objects
	 */
	public function _on_new_access_requested_api() {
		$r = Cdn_RackSpace_Api_Tokens::authenticate( $this->_config['user_name'],
			$this->_config['api_key'] );
		if ( !isset( $r['access_token'] ) || !isset( $r['services'] ) )
			throw new \Exception( 'Authentication failed' );
		$r['regions'] = Cdn_RackSpace_Api_Tokens::cdn_services_by_region(
			$r['services'] );

		if ( !isset( $r['regions'][$this->_config['region']] ) )
			throw new \Exception( 'Region ' . $this->_config['region'] . ' not found' );

		$this->_access_state['access_token'] = $r['access_token'];
		$this->_access_state['access_region_descriptor'] =
			$r['regions'][$this->_config['region']];

		$this->_create_api( array( $this, '_on_new_access_requested_second_time' ) );

		if ( !empty( $this->_new_access_state_callback ) )
			call_user_func( $this->_new_access_state_callback,
				json_encode( $this->_access_state ) );

		return $this->_api;
	}



	private function _on_new_access_requested_second_time() {
		throw new \Exception( 'Authentication failed' );
	}



	/**
	 * Purges remote files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function purge( $files, &$results ) {
		$results = array();

		try {
			foreach ( $files as $file ) {
				$url = $this->_format_url( $file['remote_path'] );
				$this->_api->purge( $this->_service_id, $url );

				$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_OK, 'OK' );
			}
		} catch ( \Exception $e ) {
			$results[] = $this->_get_result( '', '', W3TC_CDN_RESULT_HALT,
				__( 'Failed to purge: ', 'w3-total-cache' ) . $e->getMessage() );
		}

		return !$this->_is_error( $results );
	}



	public function get_domains() {
		return $this->_domains;
	}



	public function service_domains_get() {
		$service = $this->_api->service_get( $this->_service_id );

		$domains = array();

		if ( isset( $service['domains'] ) ) {
			foreach ( $service['domains'] as $d )
				$domains[] = $d['domain'];
		}

		return $domains;
	}



	public function service_domains_set( $domains ) {
		$value = array();
		foreach ( $domains as $d ) {
			$v = array( 'domain' => $d );
			if ( $this->_config['service_protocol'] == 'https' )
				$v['protocol'] = 'https';

			$value[] = $v;
		}

		$this->_api->service_set( $this->_service_id,
			array( array(
					'op' => 'replace',
					'path' => '/domains',
					'value' => $value ) ) );
	}
}
