<?php
namespace W3TC;

/**
 * StackPath REST Client Library
 */
class Cdn_StackPath2_Api {
	private $client_id;
	private $client_secret;
	private $stack_id;
	private $access_token;
	private $on_new_access_token;



	public function __construct( $config ) {
		$this->client_id = $config['client_id'];
		$this->client_secret = $config['client_secret'];
		$this->stack_id = isset( $config['stack_id'] ) ? $config['stack_id'] : '';
		$this->access_token =
			isset( $config['access_token'] ) ? $config['access_token'] : '';
		$this->on_new_access_token =
			isset( $config['on_new_access_token'] ) ? $config['on_new_access_token'] : null;
	}



	public function authenticate() {
		$request_json = array(
			'client_id' => $this->client_id,
				'client_secret' => $this->client_secret,
				'grant_type' => 'client_credentials'
		  );

		$result = wp_remote_post(
			'https://gateway.stackpath.com/identity/v1/oauth2/token',
			array(
				'headers' => array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json'
				),
				'body' => json_encode( $request_json )
			)
		);

		$r = $this->_decode_response( $result );
		if ( $r['auth_required'] ) {
			throw new \Exception( 'Authentication failed' );
		}
		if ( !isset( $r['response_json']['access_token'] ) ) {
			throw new \Exception(
				'Unexpected authentication response: access token not found' );
		}

		$this->access_token = $r['response_json']['access_token'];
		return $this->access_token;
	}


	public function site_list() {
		return $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites" );
	}



	public function site_get( $site_id ) {
		return $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites/$site_id" );
	}



	public function site_create( $data ) {
		return $this->_wp_remote_post(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites", $data );
	}



	public function site_metrics( $site_id, $days ) {
		$d = new \DateTime();

		$end_date = $d->format( 'Y-m-d' ) . 'T00:00:00Z';
		$start_date = $d->sub( new \DateInterval( 'P' . $days . 'D' ) )->format( 'Y-m-d' ) . 'T00:00:00Z';

		return $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/metrics",
			array(
				'site_id' => $site_id,
				'start_date' => $start_date,
				'end_date' => $end_date,
				'platforms' => 'CDS',
				'granularity' => 'P1D'
			)
		);
	}



	public function purge( $data ) {
		return $this->_wp_remote_post(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/purge", $data );
	}



	public function site_dns_targets_get( $site_id ) {
		return $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites/$site_id/dns/targets" );
	}



	private function site_scope_get_by_platform( $site_id, $platform ) {
		$scopes = $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites/$site_id/scopes" );
		foreach ( $scopes['results'] as $scope ) {
			if ( $scope['platform'] == $platform )
				return $scope;
		}

		return null;
	}



	public function site_cds_get( $site_id ) {
		$scope = $this->site_scope_get_by_platform( $site_id, 'CDS' );
		$scope_id = $scope['id'];

		return $this->_wp_remote_get(
			"https://gateway.stackpath.com/cdn/v1/stacks/$this->stack_id/sites/$site_id/scopes/$scope_id/configuration" );
	}


	public function stacks_list() {
		return $this->_wp_remote_get( 'https://gateway.stackpath.com/stack/v1/stacks' );
	}



	public function stack_get( $stack_id ) {
		return $this->_wp_remote_get( "https://gateway.stackpath.com/stack/v1/stacks/$stack_id" );
	}



	private function _decode_response( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) )
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['body'] );

		if ( $result['response']['code'] == '401' ) {
			return array(
				'auth_required' => true,
				'response_json' => array()
			);
		}

		if ( $result['response']['code'] != '200' && $result['response']['code'] != '201' ) {
			if ( isset( $response_json['message'] ) ) {
				throw new \Exception( $response_json['message'] );
			} else {
				throw new \Exception( 'response code ' .
					$result['response']['code'] . ' with ' . $result['body'] );
			}
		}

			return array(
				'auth_required' => false,
				'response_json' => $response_json
			);
	}



	private function _wp_remote_get( $url, $data = array() ) {
		//var_dump( $url );
		//var_dump( array( 'headers' => 'authorization: Bearer ' . $this->access_token ) );

		if ( !empty( $this->access_token ) ) {
			$result = wp_remote_get(
				$url . ( empty( $data ) ? '' : '?' . http_build_query( $data ) ),
				array(
					'headers' => 'authorization: Bearer ' . $this->access_token
				)
			);

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] ) {
				return $r['response_json'];
			}
		}

		$this->authenticate();
		if ( !is_null( $this->on_new_access_token ) ) {
			call_user_func( $this->on_new_access_token, $this->access_token );
		}

		return $this->_wp_remote_get( $url, $data );
	}



	private function _wp_remote_post( $url, $data ) {
		if ( !empty( $this->access_token ) ) {
			add_filter( 'http_request_timeout', array( $this, 'filter_timeout_time' ) );
			add_filter( 'https_ssl_verify', array( $this, 'https_ssl_verify' ) );

			$result = wp_remote_post( $url, array(
					'headers' => array(
						'authorization' => 'Bearer ' . $this->access_token,
						'Accept' => 'application/json',
						'Content-Type' => 'application/json'
					),
					'body' => json_encode( $data )
				) );

			remove_filter( 'https_ssl_verify', array( $this, 'https_ssl_verify' ) );
			remove_filter( 'http_request_timeout', array( $this, 'filter_timeout_time' ) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] ) {
				return $r['response_json'];
			}
		}

		$this->authenticate();
		if ( !is_null( $this->on_new_access_token ) ) {
			call_user_func( $this->on_new_access_token, $this->access_token );
		}

		return $this->_wp_remote_post( $url, $data );
	}



	/**
	 * Increase http request timeout to 60 seconds
	 */
	public function filter_timeout_time($time) {
		return 600;
	}

	/**
	 * Don't check certificate, some users have limited CA list
	 */
	public function https_ssl_verify($v) {
		return false;
	}
}
