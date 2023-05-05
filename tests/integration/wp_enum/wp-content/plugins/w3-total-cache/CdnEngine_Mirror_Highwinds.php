<?php
namespace W3TC;

/**
 * class CdnEngine_Mirror_Highwinds
 */
class CdnEngine_Mirror_Highwinds extends CdnEngine_Mirror {
	private $api;
	private $domains;
	private $host_hash_code;

	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 * account_hash
	 * username
	 * password
	 * host_hash_code
	 */
	function __construct( $config = array() ) {
		$this->api = new Cdn_Highwinds_Api( $config['account_hash'],
			$config['api_token'] );
		$this->host_hash_code = $config['host_hash_code'];

		if ( !empty( $config['domains'] ) )
			$this->domains = (array)$config['domains'];
		else
			$this->domains = array(
				'cds.' . $config['host_hash_code'] . '.hwcdn.net' );

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
		$results = array();
		try {
			$urls = array();
			foreach ( $files as $file )
				$urls[] = $this->_format_url( $file['remote_path'] );
			$this->api->purge( $urls, false );

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
		$results = array();
		try {
			$urls = array();
			foreach ( $this->domains as $domain ) {
				$urls[] = 'http://' . $domain . '/';
				$urls[] = 'https://' . $domain . '/';
			}

			$this->api->purge( $urls, true );

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



	public function service_analytics_transfer() {
		$start_date = gmdate( 'Y-m-d', strtotime( '-30 days', time() ) ) . 'T00:00:00Z';
		$end_date = gmdate( 'Y-m-d' ) . 'T00:00:00Z';

		$response = $this->api->analytics_transfer( $this->host_hash_code,
			'P1D', 'CDS', $start_date, $end_date );
		if ( !isset( $response['series'] ) || !is_array( $response['series'] ) ||
			count( $response['series'] ) < 1 )
			throw new \Exception( 'cant parse response' );

		$series = $response['series'][0];
		if ( !isset( $series['metrics'] ) || !is_array( $series['metrics'] ) )
			throw new \Exception( 'cant parse response - no metrics' );

		$metrics = $series['metrics'];
		if ( !isset( $series['metrics'] ) || !is_array( $series['data'] ) )
			throw new \Exception( 'cant parse response - no metrics' );

		$output = array();
		foreach ( $series['data'] as $data ) {
			$item = array();
			for ( $m = 0; $m < count( $metrics ); $m++ )
				$item[$metrics[$m]] = $data[$m];

			$output[] = $item;
		}

		return $output;
	}



	public function service_cnames_get() {
		$scope_id = $this->_get_scope_id();
		$configuration = $this->api->configure_scope_get( $this->host_hash_code,
			$scope_id );

		$domains = array();

		if ( isset( $configuration['hostname'] ) ) {
			foreach ( $configuration['hostname'] as $d )
				$domains[] = $d['domain'];
		}

		return $domains;
	}



	public function service_cnames_set( $domains ) {
		$scope_id = $this->_get_scope_id();
		$configuration = $this->api->configure_scope_get( $this->host_hash_code,
			$scope_id );

		$hostname = array();
		foreach ( $domains as $d )
			$hostname[] = array( 'domain' => $d );

		$configuration['hostname'] = $hostname;
		$this->api->configure_scope_set( $this->host_hash_code,
			$scope_id, $configuration );
	}



	private function _get_scope_id() {
		$scopes_response = $this->api->configure_scopes( $this->host_hash_code );
		$scope_id = 0;

		foreach ( $scopes_response['list'] as $scope ) {
			if ( $scope['platform'] == 'CDS' )
				return $scope['id'];
		}

		throw new Exception( 'scope CDN hasnt been created' );
	}
}
