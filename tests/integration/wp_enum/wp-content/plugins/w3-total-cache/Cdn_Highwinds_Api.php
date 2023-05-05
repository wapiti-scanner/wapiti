<?php
namespace W3TC;



class Cdn_Highwinds_Api {
	static private $root_uri = 'https://striketracker3.highwinds.com';
	private $account_hash;
	private $api_token;



	static public function users_me( $api_token ) {
		$result = wp_remote_get( self::$root_uri . '/api/v1/users/me', array(
				'headers' => 'Authorization: Bearer ' . $api_token
			) );

		$r = self::_decode_response( $result );
		if ( !$r['auth_required'] )
			return $r['response_json'];

		throw new \Exception( 'Authentication failed' );
	}



	public function __construct( $account_hash, $api_token ) {
		$this->account_hash = $account_hash;
		$this->api_token = $api_token;
	}



	public function analytics_transfer( $host, $granularity, $platforms,
		$start_date, $end_date ) {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash .
			'/analytics/transfer?startDate=' . urlencode( $start_date ) .
			'&endDate=' . urlencode( $end_date ) .
			'&granularity=' . urlencode( $granularity ) .
			'&platforms=' . urlencode( $platforms ) );
	}



	public function configure_scopes( $host ) {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash .
			'/hosts/' . $host . '/configuration/scopes' );
	}



	public function configure_scope_get( $host, $scope_id ) {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash .
			'/hosts/' . $host . '/configuration/' . $scope_id );
	}



	public function configure_scope_set( $host, $scope_id, $configuration ) {
		return $this->_wp_remote_put(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash .
			'/hosts/' . $host . '/configuration/' . $scope_id,
			json_encode( $configuration )
		);
	}



	public function host_add( $host ) {
		return $this->_wp_remote_post(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/hosts',
			json_encode( $host )
		);
	}



	public function hosts() {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/hosts' );
	}



	public function origin_add( $origin ) {
		return $this->_wp_remote_post(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/origins',
			json_encode( $origin )
		);
	}



	public function origins() {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/origins' );
	}



	/**
	 * $recursive - true/false
	 */
	public function purge( $urls, $recursive ) {
		$list = array();
		foreach ( $urls as $url ) {
			$list[] = array(
				'url' => $url,
				'recursive' => $recursive );
		}

		$response = $this->_wp_remote_post(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/purge',
			json_encode( array( 'list' => $list ) )
		);
	}



	public function services() {
		return $this->_wp_remote_get(
			self::$root_uri . '/api/v1/accounts/' . $this->account_hash . '/services'
		);
	}



	private function _wp_remote_get( $url, $body = array() ) {
		$result = wp_remote_get( $url, array(
				'headers' => 'Authorization: Bearer ' . $this->api_token,
				'body' => $body
			) );

		$r = self::_decode_response( $result );
		if ( !$r['auth_required'] )
			return $r['response_json'];

		throw new \Exception( 'Authentication failed' );
	}



	private function _wp_remote_post( $url, $body ) {
		$headers = array(
			'Authorization' => 'Bearer ' . $this->api_token
		);
		if ( !is_array( $body ) )
			$headers['Content-Type'] = 'application/json';

		$result = wp_remote_post( $url, array(
				'headers' => $headers,
				'body' => $body
			) );

		$r = self::_decode_response( $result );
		if ( !$r['auth_required'] )
			return $r['response_json'];

		throw new \Exception( 'Authentication failed' );
	}



	private function _wp_remote_put( $url, $body ) {
		$headers = array(
			'Authorization' => 'Bearer ' . $this->api_token
		);
		if ( !is_array( $body ) )
			$headers['Content-Type'] = 'application/json';

		$result = wp_remote_post( $url, array(
				'headers' => $headers,
				'body' => $body,
				'method' => 'PUT'
			) );

		$r = self::_decode_response( $result );
		if ( !$r['auth_required'] )
			return $r['response_json'];

		throw new \Exception( 'Authentication failed' );
	}



	static private function _decode_response( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) ) {
			if ( $result['response']['code'] == '200' && empty( $result['body'] ) )
				return array(
					'response_json' => array(),
					'auth_required' => false
				);

			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['body'] );
		}

		if ( isset( $response_json['error'] ) ) {
			if ( isset( $response_json['code'] ) && $response_json['code'] == '203' )
				return array( 'response_json' => $response_json, 'auth_required' => true );

			throw new \Exception( $response_json['error'] );
		}

		if ( $result['response']['code'] != '200' && $result['response']['code'] != '201' )
			throw new \Exception( $result['body'] );

		return array( 'response_json' => $response_json, 'auth_required' => false );
	}
}
